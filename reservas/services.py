from datetime import datetime, timedelta

from django.utils import timezone

from .models import Reserva


ANTICIPACION_CANCELACION_CLIENTE = timedelta(minutes=30)
ANTICIPACION_CHECKIN = timedelta(minutes=30)


def fecha_hora_reserva(reserva, campo_hora):
    hora = getattr(reserva, campo_hora)
    fecha_hora = datetime.combine(reserva.fecha, hora)
    return timezone.make_aware(fecha_hora, timezone.get_current_timezone())


def validar_cancelacion_cliente(reserva, ahora=None):
    ahora = timezone.localtime(ahora or timezone.now())
    limite = fecha_hora_reserva(reserva, 'hora_inicio') - ANTICIPACION_CANCELACION_CLIENTE

    if ahora > limite:
        return False, 'No puedes cancelar esta reserva con menos de 30 minutos de anticipación.'

    return True, ''


def validar_horario_checkin(reserva, ahora=None):
    ahora = timezone.localtime(ahora or timezone.now())
    inicio = fecha_hora_reserva(reserva, 'hora_inicio')
    fin = fecha_hora_reserva(reserva, 'hora_fin')
    apertura_checkin = inicio - ANTICIPACION_CHECKIN

    if ahora < apertura_checkin:
        return False, (
            'El check-in solo puede realizarse desde 30 minutos antes de la hora de la reserva.'
        )

    if ahora >= fin:
        return False, 'No se puede realizar el check-in porque el horario de la reserva ya terminó.'

    return True, ''


def actualizar_estado_mesa(mesa):
    reservas_activas = Reserva.objects.filter(
        mesa=mesa,
        estado__in=['pendiente', 'confirmada', 'en_curso'],
    )

    if reservas_activas.filter(estado='en_curso').exists():
        mesa.estado = 'ocupada'
    elif reservas_activas.exists():
        mesa.estado = 'reservada'
    else:
        mesa.estado = 'disponible'

    mesa.save(update_fields=['estado'])


def _cancelar_preorden_de_reserva_vencida(reserva):
    preorden = reserva.preordenes.exclude(estado__in=['cancelada', 'con_pedido', 'entregada']).first()
    if not preorden:
        return

    if preorden.estado == 'apartada':
        for detalle in preorden.detalles.select_related('producto').all():
            producto = detalle.producto
            if producto.stock_reservado > 0:
                producto.stock_reservado = max(0, producto.stock_reservado - detalle.cantidad)
                producto.save(update_fields=['stock_reservado'])

    preorden.estado = 'cancelada'
    preorden.save(update_fields=['estado'])


def sincronizar_reservas_vencidas(ahora=None):
    """
    Cierra reservas vencidas al consultar el sistema y libera sus mesas.

    Las reservas en curso pasan a finalizadas. Las pendientes o confirmadas
    que terminaron sin check-in pasan a no_asistio.
    """
    ahora = timezone.localtime(ahora or timezone.now())
    candidatas = (
        Reserva.objects.filter(
            estado__in=['pendiente', 'confirmada', 'en_curso'],
            fecha__lte=ahora.date(),
        )
        .select_related('mesa')
        .order_by('fecha', 'hora_fin')
    )

    mesas_afectadas = {}
    for reserva in candidatas:
        if fecha_hora_reserva(reserva, 'hora_fin') > ahora:
            continue

        estaba_en_curso = reserva.estado == 'en_curso'
        reserva.estado = 'finalizada' if estaba_en_curso else 'no_asistio'
        reserva.save(update_fields=['estado'])
        if not estaba_en_curso:
            _cancelar_preorden_de_reserva_vencida(reserva)
        mesas_afectadas[reserva.mesa_id] = reserva.mesa

    for mesa in mesas_afectadas.values():
        actualizar_estado_mesa(mesa)

    return len(mesas_afectadas)
