from django.db import transaction
from django.http import JsonResponse
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from pedidos.services import cancelar_preorden_por_reserva, convertir_preorden_a_pedido_por_checkin
from reservas.models import Reserva
from reservas.services import (
    actualizar_estado_mesa,
    sincronizar_reservas_vencidas,
    validar_horario_checkin,
)
from reservas.views import IsEmpleadoOrAdmin, JWTAuthentication


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsEmpleadoOrAdmin])
def reservas_pendientes(request):
    sincronizar_reservas_vencidas()
    reservas = Reserva.objects.filter(estado='confirmada').select_related(
        'cliente__id_usuario',
        'mesa',
        'sala',
    )

    data = []
    for reserva in reservas:
        puede_hacer_checkin, mensaje_checkin = validar_horario_checkin(reserva)
        data.append({
            'id': reserva.id,
            'cliente': reserva.cliente.id_usuario.nombre,
            'sala': reserva.sala.nombre,
            'mesa': reserva.mesa.nombre,
            'fecha': str(reserva.fecha),
            'hora_inicio': str(reserva.hora_inicio),
            'estado': reserva.estado,
            'puede_hacer_checkin': puede_hacer_checkin,
            'mensaje_checkin': mensaje_checkin,
        })

    return JsonResponse(data, safe=False)


@api_view(['PATCH'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsEmpleadoOrAdmin])
def checkin_reserva(request, reserva_id):
    sincronizar_reservas_vencidas()
    try:
        reserva = Reserva.objects.get(id=reserva_id)
    except Reserva.DoesNotExist:
        return JsonResponse({'error': 'Reserva no encontrada'}, status=404)

    if reserva.estado != 'confirmada':
        return JsonResponse({'error': 'Solo reservas confirmadas pueden iniciar'}, status=400)

    puede_hacer_checkin, mensaje = validar_horario_checkin(reserva)
    if not puede_hacer_checkin:
        return JsonResponse({'error': mensaje}, status=400)

    with transaction.atomic():
        reserva.estado = 'en_curso'
        reserva.save(update_fields=['estado'])
        reserva.mesa.estado = 'ocupada'
        reserva.mesa.save(update_fields=['estado'])

    info_preorden = convertir_preorden_a_pedido_por_checkin(reserva, request.user)
    return JsonResponse({'mensaje': 'Check-in realizado correctamente', **info_preorden})


@api_view(['PATCH'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsEmpleadoOrAdmin])
def marcar_no_asistio(request, reserva_id):
    sincronizar_reservas_vencidas()
    try:
        reserva = Reserva.objects.get(id=reserva_id)
    except Reserva.DoesNotExist:
        return JsonResponse({'error': 'Reserva no encontrada'}, status=404)

    if reserva.estado != 'confirmada':
        return JsonResponse(
            {'error': 'Solo una reserva confirmada puede marcarse como no asistió'},
            status=400,
        )

    reserva.estado = 'no_asistio'
    reserva.save(update_fields=['estado'])
    actualizar_estado_mesa(reserva.mesa)
    cancelar_preorden_por_reserva(reserva, request.user)

    return JsonResponse({'mensaje': 'Reserva marcada como no asistió'})
