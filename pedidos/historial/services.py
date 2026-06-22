from datetime import datetime
from django.db.models import Q
from ..models import Pedido


def filtrar_pedidos(params, user=None):
    qs = (
        Pedido.objects.select_related(
            'usuario',
            'usuario__cod_rol',
            'cliente__id_usuario',
            'reserva__cliente__id_usuario',
            'reserva__sala',
            'reserva__mesa',
            'sala',
            'mesa',
        )
        .prefetch_related('detalles__producto')
        .prefetch_related('reserva__preordenes__usuario_mesero__cod_rol')
        .all()
    )

    fecha_inicio = params.get('fecha_inicio')
    fecha_fin = params.get('fecha_fin')
    fecha = params.get('fecha')
    estado = params.get('estado')
    cliente = params.get('cliente')

    # Filtrado por rango de fechas (created_at)
    try:
        if fecha:
            d = datetime.fromisoformat(fecha).date()
            qs = qs.filter(created_at__date=d)
        else:
            if fecha_inicio:
                d = datetime.fromisoformat(fecha_inicio).date()
                qs = qs.filter(created_at__date__gte=d)
            if fecha_fin:
                d2 = datetime.fromisoformat(fecha_fin).date()
                qs = qs.filter(created_at__date__lte=d2)
    except Exception:
        # Ignorar formato inválido y dejar que la vista maneje validación
        pass

    if estado:
        qs = qs.filter(estado=estado)

    # Si el usuario es cliente, solo ver sus pedidos
    if user and getattr(user, 'cod_rol', None) and user.cod_rol.cod_rol == 'cliente':
        qs = qs.filter(
            Q(usuario=user)
            | Q(cliente__id_usuario=user)
            | Q(reserva__cliente__id_usuario=user)
        )
    else:
        # Filtrar por cliente real cuando el pedido viene de una reserva.
        if cliente:
            if cliente.isdigit():
                qs = qs.filter(
                    Q(cliente__id_usuario__id_usuario=int(cliente))
                    | Q(reserva__cliente__id_usuario__id_usuario=int(cliente))
                )
            else:
                qs = qs.filter(
                    Q(cliente__id_usuario__nombre__icontains=cliente)
                    | Q(reserva__cliente__id_usuario__nombre__icontains=cliente)
                )

    return qs.order_by('-created_at')
