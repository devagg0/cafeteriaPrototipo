from .models import Preorden, Pedido, DetallePedido
from usuarios.models import Bitacora

def cancelar_preorden_por_reserva(reserva, usuario):
    preorden = Preorden.objects.filter(reserva=reserva).first()
    if not preorden:
        return {}
    if preorden.estado in ['con_pedido', 'entregada']:
        return {
            'preorden_id': preorden.id,
            'preorden_cancelada': False,
            'preorden_estado': preorden.estado,
            'preorden_aviso': (
                f'La preorden #{preorden.id} ya estaba en "{preorden.estado}" '
                f'y no fue modificada.'
            ),
        }
    if preorden.estado == 'cancelada':
        return {'preorden_id': preorden.id, 'preorden_cancelada': False, 'preorden_estado': 'cancelada'}
    if preorden.estado == 'apartada':
        for detalle in preorden.detalles.select_related('producto').all():
            p = detalle.producto
            if p.stock_reservado > 0:
                p.stock_reservado = max(0, p.stock_reservado - detalle.cantidad)
                p.save()
    estado_anterior = preorden.estado
    preorden.estado = 'cancelada'
    preorden.save()
    Bitacora.objects.create(
        usuario=usuario,
        accion='cancelar preorden (cascada reserva)',
        detalles=(
            f'Preorden {preorden.id} cancelada automáticamente '
            f'(antes: {estado_anterior}) — Reserva {reserva.id}'
        ),
    )
    return {
        'preorden_id': preorden.id,
        'preorden_cancelada': True,
        'preorden_estado_anterior': estado_anterior,
    }

def convertir_preorden_a_pedido_por_checkin(reserva, usuario):
    preorden = Preorden.objects.filter(reserva=reserva).first()
    if not preorden:
        return {}
    estados_procesables = ['programada', 'pendiente', 'apartada', 'sin_stock']
    if preorden.estado not in estados_procesables:
        return {
            'preorden_id': preorden.id,
            'preorden_estado': preorden.estado,
            'preorden_procesada': False,
        }
    if Pedido.objects.filter(reserva=reserva).exists():
        return {
            'preorden_id': preorden.id,
            'preorden_estado': preorden.estado,
            'preorden_procesada': False,
            'motivo': 'El pedido ya había sido creado para esta reserva.',
        }
    faltantes = []
    for detalle in preorden.detalles.select_related('producto').all():
        if detalle.cantidad > detalle.producto.stock:
            faltantes.append(
                f'"{detalle.producto.nombre}": necesario {detalle.cantidad}, '
                f'disponible {detalle.producto.stock}'
            )
    if faltantes:
        preorden.estado = 'sin_stock'
        preorden.save()
        Bitacora.objects.create(
            usuario=usuario,
            accion='preorden → sin_stock (check-in)',
            detalles=f'Preorden {preorden.id} — Reserva {reserva.id}: {"; ".join(faltantes)}',
        )
        return {
            'preorden_id': preorden.id,
            'preorden_estado': 'sin_stock',
            'preorden_procesada': False,
            'faltantes': faltantes,
        }
    total = sum(d.subtotal for d in preorden.detalles.all())
    usuario_mesero = getattr(preorden, 'usuario_mesero', None)
    usuario_pedido = usuario_mesero or usuario
    pedido = Pedido.objects.create(
        reserva=reserva,
        sala=reserva.sala,
        mesa=reserva.mesa,
        usuario=usuario_pedido,
        total=total,
        estado='confirmado',
    )
    for detalle in preorden.detalles.select_related('producto').all():
        DetallePedido.objects.create(
            pedido=pedido,
            producto=detalle.producto,
            cantidad=detalle.cantidad,
            precio_unitario=detalle.precio_unitario,
            subtotal=detalle.subtotal,
        )
        p = detalle.producto
        p.stock -= detalle.cantidad
        p.save()
    preorden.estado = 'con_pedido'
    preorden.save()
    Bitacora.objects.create(
        usuario=usuario,
        accion='preorden → con_pedido (check-in)',
        detalles=(
            f'Preorden {preorden.id} → Pedido {pedido.id}; '
            f'Reserva {reserva.id}; operador_checkin={usuario.nombre}; '
            f'mesero_responsable={usuario_mesero.nombre if usuario_mesero else "Sin mesero asignado"}'
        ),
    )
    return {
        'preorden_id': preorden.id,
        'preorden_estado': 'con_pedido',
        'preorden_procesada': True,
        'pedido_id': pedido.id,
    }
