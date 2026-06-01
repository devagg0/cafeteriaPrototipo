from datetime import datetime
from django.db.models import Q
from ..models import Pedido


def filtrar_pedidos(params, user=None):
    qs = (
        Pedido.objects.select_related('usuario')
        .prefetch_related('detalles__producto')
        .all()
    )

    fecha_inicio = params.get('fecha_inicio')
    fecha_fin = params.get('fecha_fin')
    estado = params.get('estado')
    cliente = params.get('cliente')

    # Filtrado por rango de fechas (created_at)
    try:
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
        qs = qs.filter(usuario=user)
    else:
        # Si se pasa cliente como query param, intentar filtrar por id o por nombre
        if cliente:
            if cliente.isdigit():
                qs = qs.filter(usuario__id_usuario=int(cliente))
            else:
                qs = qs.filter(usuario__nombre__icontains=cliente)

    return qs.order_by('-created_at')
