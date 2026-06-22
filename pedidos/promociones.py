from decimal import Decimal

from django.utils import timezone


ZERO = Decimal('0.00')


def calcular_descuento_pedido(pedido, promocion=None):
    promocion = promocion or pedido.promocion
    if not promocion or not promocion.activa:
        return ZERO

    hoy = timezone.localdate()
    if not promocion.fecha_inicio <= hoy <= promocion.fecha_fin:
        return ZERO

    productos_ids = set(promocion.productos.values_list('id', flat=True))
    categorias_ids = set(promocion.categorias.values_list('id', flat=True))
    aplica_a_todo = not productos_ids and not categorias_ids

    base = ZERO
    for detalle in pedido.detalles.select_related('producto__categoria'):
        producto = detalle.producto
        if (
            aplica_a_todo
            or producto.id in productos_ids
            or producto.categoria_id in categorias_ids
        ):
            base += detalle.subtotal

    if base <= ZERO:
        return ZERO
    if promocion.tipo_descuento == 'porcentaje':
        descuento = base * promocion.valor_descuento / Decimal('100')
    else:
        descuento = min(promocion.valor_descuento, base)
    return descuento.quantize(Decimal('0.01'))


def recalcular_totales_pedido(pedido, guardar=True):
    subtotal = sum(
        (detalle.subtotal for detalle in pedido.detalles.all()),
        ZERO,
    )
    pedido.descuento = calcular_descuento_pedido(pedido)
    pedido.total = max(ZERO, subtotal - pedido.descuento)
    if guardar:
        pedido.save(update_fields=['descuento', 'total', 'updated_at'])
    return pedido.total


def total_confirmado_pendiente(pedido, total_pagado=ZERO):
    total_confirmado = sum(
        (detalle.subtotal for detalle in pedido.detalles.filter(confirmado=True)),
        ZERO,
    )
    descuento = min(pedido.descuento or ZERO, total_confirmado)
    return max(ZERO, total_confirmado - descuento - (total_pagado or ZERO))
