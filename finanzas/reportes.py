from datetime import timedelta
from decimal import Decimal

from django.db.models import Count, DecimalField, ExpressionWrapper, F, IntegerField, Sum
from django.db.models.functions import Coalesce, TruncDate
from django.utils import timezone

from finanzas.models import Pago
from pedidos.models import DetallePedido, DetallePreorden, Pedido, Preorden
from producto.models import Producto
from reservas.models import Mesa, Reserva, SalaTematica


PAGO_EXITOSO = 'exitoso'
PEDIDO_CANCELADO = 'cancelado'
RESERVA_ACTIVA_ESTADOS = ['pendiente', 'confirmada', 'en_curso']
PREORDEN_DEMANDA_ESTADOS = ['programada', 'apartada', 'sin_stock']
PREORDEN_CONVERTIDA_ESTADO = 'con_pedido'


def decimal_to_float(value):
    if value is None:
        return 0.0
    if isinstance(value, Decimal):
        return float(value)
    return value


def parse_positive_int(value, default):
    try:
        parsed = int(value)
        return parsed if parsed >= 0 else default
    except (TypeError, ValueError):
        return default


def parse_date_range(params):
    today = timezone.localdate()
    default_start = today.replace(day=1)
    fecha_inicio = params.get('fecha_inicio')
    fecha_fin = params.get('fecha_fin')

    if fecha_inicio:
        fecha_inicio = timezone.datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
    else:
        fecha_inicio = default_start

    if fecha_fin:
        fecha_fin = timezone.datetime.strptime(fecha_fin, '%Y-%m-%d').date()
    else:
        fecha_fin = today

    if fecha_inicio > fecha_fin:
        fecha_inicio, fecha_fin = fecha_fin, fecha_inicio

    return fecha_inicio, fecha_fin


def rango_payload(fecha_inicio, fecha_fin):
    return {
        'fecha_inicio': fecha_inicio.isoformat(),
        'fecha_fin': fecha_fin.isoformat(),
    }


def ingresos_confirmados(fecha_inicio, fecha_fin):
    pagos = Pago.objects.filter(
        estado=PAGO_EXITOSO,
        created_at__date__gte=fecha_inicio,
        created_at__date__lte=fecha_fin,
    )
    total = pagos.aggregate(total=Coalesce(Sum('monto'), Decimal('0')))['total']
    por_dia = [
        {'fecha': row['dia'].isoformat(), 'total': decimal_to_float(row['total'])}
        for row in pagos.annotate(dia=TruncDate('created_at'))
        .values('dia')
        .annotate(total=Coalesce(Sum('monto'), Decimal('0')))
        .order_by('dia')
    ]
    por_metodo = [
        {
            'metodo_pago': row['metodo_pago'],
            'cantidad': row['cantidad'],
            'total': decimal_to_float(row['total']),
        }
        for row in pagos.values('metodo_pago')
        .annotate(cantidad=Count('id'), total=Coalesce(Sum('monto'), Decimal('0')))
        .order_by('metodo_pago')
    ]
    return {
        'total': decimal_to_float(total),
        'cantidad_pagos': pagos.count(),
        'por_dia': por_dia,
        'por_metodo': por_metodo,
        'origenes': {
            'pedido': pagos.filter(pedido__isnull=False).count(),
            'reserva': pagos.filter(reserva__isnull=False).count(),
            'preorden': pagos.filter(preorden__isnull=False).count(),
        },
    }


def ventas_reales(fecha_inicio, fecha_fin):
    pedidos = Pedido.objects.exclude(estado=PEDIDO_CANCELADO).filter(
        created_at__date__gte=fecha_inicio,
        created_at__date__lte=fecha_fin,
    )
    total = pedidos.aggregate(total=Coalesce(Sum('total'), Decimal('0')))['total']
    detalles = DetallePedido.objects.filter(pedido__in=pedidos)
    productos = [
        {
            'producto_id': row['producto_id'],
            'producto': row['producto__nombre'],
            'cantidad': row['cantidad'] or 0,
            'total': decimal_to_float(row['total']),
        }
        for row in detalles.values('producto_id', 'producto__nombre')
        .annotate(
            cantidad=Coalesce(Sum('cantidad'), 0),
            total=Coalesce(Sum('subtotal'), Decimal('0')),
        )
        .order_by('-cantidad', 'producto__nombre')
    ]
    por_estado = [
        {'estado': row['estado'], 'cantidad': row['cantidad']}
        for row in pedidos.values('estado').annotate(cantidad=Count('id')).order_by('estado')
    ]
    return {
        'cantidad_pedidos': pedidos.count(),
        'total_vendido': decimal_to_float(total),
        'por_producto': productos,
        'por_estado': por_estado,
    }


def resumen_reservas(fecha_inicio, fecha_fin):
    reservas = Reserva.objects.filter(fecha__gte=fecha_inicio, fecha__lte=fecha_fin)
    por_estado = [
        {'estado': row['estado'], 'cantidad': row['cantidad']}
        for row in reservas.values('estado').annotate(cantidad=Count('id')).order_by('estado')
    ]
    por_sala = [
        {
            'sala_id': row['sala_id'],
            'sala': row['sala__nombre'],
            'cantidad': row['cantidad'],
            'personas': row['personas'] or 0,
        }
        for row in reservas.values('sala_id', 'sala__nombre')
        .annotate(cantidad=Count('id'), personas=Coalesce(Sum('cantidad_personas'), 0))
        .order_by('sala__nombre')
    ]
    return {
        'total': reservas.count(),
        'activas': reservas.filter(estado__in=RESERVA_ACTIVA_ESTADOS).count(),
        'por_estado': por_estado,
        'por_sala': por_sala,
    }


def resumen_preordenes(fecha_inicio, fecha_fin):
    preordenes = Preorden.objects.filter(
        created_at__date__gte=fecha_inicio,
        created_at__date__lte=fecha_fin,
    )
    demanda = preordenes.filter(estado__in=PREORDEN_DEMANDA_ESTADOS)
    total_demanda = demanda.aggregate(total=Coalesce(Sum('total'), Decimal('0')))['total']
    productos = [
        {
            'producto_id': row['producto_id'],
            'producto': row['producto__nombre'],
            'cantidad': row['cantidad'] or 0,
            'total': decimal_to_float(row['total']),
        }
        for row in DetallePreorden.objects.filter(preorden__in=demanda)
        .values('producto_id', 'producto__nombre')
        .annotate(
            cantidad=Coalesce(Sum('cantidad'), 0),
            total=Coalesce(Sum('subtotal'), Decimal('0')),
        )
        .order_by('-cantidad', 'producto__nombre')
    ]
    por_estado = [
        {'estado': row['estado'], 'cantidad': row['cantidad']}
        for row in preordenes.values('estado').annotate(cantidad=Count('id')).order_by('estado')
    ]
    return {
        'total': preordenes.count(),
        'demanda_anticipada': demanda.count(),
        'convertidas_a_pedido': preordenes.filter(estado=PREORDEN_CONVERTIDA_ESTADO).count(),
        'total_demanda_anticipada': decimal_to_float(total_demanda),
        'por_estado': por_estado,
        'productos_demandados': productos,
    }


def ocupacion_salas(fecha_inicio, fecha_fin):
    total_dias = max((fecha_fin - fecha_inicio).days + 1, 1)
    salas = SalaTematica.objects.all().order_by('nombre')
    resultado = []

    for sala in salas:
        mesas_activas = Mesa.objects.filter(sala=sala, activa=True)
        total_mesas = mesas_activas.count()
        mesas_ocupadas = mesas_activas.filter(estado__in=['ocupada', 'reservada', 'atendida']).count()
        reservas_periodo = Reserva.objects.filter(
            sala=sala,
            fecha__gte=fecha_inicio,
            fecha__lte=fecha_fin,
        ).exclude(estado='cancelada').count()
        capacidad_periodo = total_mesas * total_dias
        ocupacion_periodo = (reservas_periodo / capacidad_periodo * 100) if capacidad_periodo else 0
        ocupacion_actual = (mesas_ocupadas / total_mesas * 100) if total_mesas else 0

        resultado.append({
            'sala_id': sala.id,
            'sala': sala.nombre,
            'habilitada': sala.habilitada,
            'mesas_activas': total_mesas,
            'mesas_ocupadas_o_reservadas': mesas_ocupadas,
            'reservas_periodo': reservas_periodo,
            'ocupacion_actual': round(ocupacion_actual, 2),
            'ocupacion_periodo': round(ocupacion_periodo, 2),
        })

    promedio_actual = sum(row['ocupacion_actual'] for row in resultado) / len(resultado) if resultado else 0
    return {
        'promedio_actual': round(promedio_actual, 2),
        'por_sala': resultado,
    }


def inventario_critico(umbral_stock):
    stock_disponible_expr = ExpressionWrapper(
        F('stock') - F('stock_reservado'),
        output_field=IntegerField(),
    )
    productos = (
        Producto.objects.filter(estado=True)
        .annotate(stock_disponible_calc=stock_disponible_expr)
        .filter(stock_disponible_calc__lte=umbral_stock)
        .select_related('categoria')
        .order_by('stock_disponible_calc', 'nombre')
    )
    return [
        {
            'producto_id': producto.id,
            'producto': producto.nombre,
            'categoria': producto.categoria.nombre if producto.categoria_id else None,
            'precio': decimal_to_float(producto.precio),
            'stock': producto.stock,
            'stock_reservado': producto.stock_reservado,
            'stock_disponible': producto.stock_disponible_calc,
            'umbral': umbral_stock,
        }
        for producto in productos
    ]


def reporte_estatico(params):
    fecha_inicio, fecha_fin = parse_date_range(params)
    umbral_stock = parse_positive_int(params.get('umbral_stock'), 5)

    ingresos = ingresos_confirmados(fecha_inicio, fecha_fin)
    ventas = ventas_reales(fecha_inicio, fecha_fin)
    reservas = resumen_reservas(fecha_inicio, fecha_fin)
    preordenes = resumen_preordenes(fecha_inicio, fecha_fin)
    ocupacion = ocupacion_salas(fecha_inicio, fecha_fin)
    inventario = inventario_critico(umbral_stock)

    return {
        'modo': 'estatico',
        'rango': rango_payload(fecha_inicio, fecha_fin),
        'tarjetas': {
            'ingresos_confirmados': ingresos['total'],
            'ventas_reales': ventas['cantidad_pedidos'],
            'reservas_totales': reservas['total'],
            'preordenes_activas': preordenes['demanda_anticipada'],
            'ocupacion_promedio': ocupacion['promedio_actual'],
            'productos_criticos': len(inventario),
        },
        'graficos': {
            'ingresos_por_dia': ingresos['por_dia'],
            'ventas_por_producto': ventas['por_producto'],
            'reservas_por_estado': reservas['por_estado'],
            'ocupacion_por_sala': ocupacion['por_sala'],
        },
        'tablas': {
            'inventario_critico': inventario,
            'preordenes_por_estado': preordenes['por_estado'],
            'pagos_por_metodo': ingresos['por_metodo'],
        },
        'notas': [
            'Los ingresos salen solo de pagos exitosos.',
            'Las ventas reales salen de pedidos no cancelados.',
            'Las preordenes se reportan como demanda anticipada, no como ingreso final.',
        ],
    }


def reporte_dinamico(params):
    fecha_inicio, fecha_fin = parse_date_range(params)
    tipo = (params.get('tipo') or 'ventas').lower()
    agrupar_por = (params.get('agrupar_por') or '').lower()
    umbral_stock = parse_positive_int(params.get('umbral_stock'), 5)

    handlers = {
        'ingresos': lambda: _dinamico_ingresos(fecha_inicio, fecha_fin, agrupar_por),
        'ventas': lambda: _dinamico_ventas(fecha_inicio, fecha_fin, agrupar_por),
        'reservas': lambda: _dinamico_reservas(fecha_inicio, fecha_fin, agrupar_por),
        'preordenes': lambda: _dinamico_preordenes(fecha_inicio, fecha_fin, agrupar_por),
        'ocupacion': lambda: _dinamico_ocupacion(fecha_inicio, fecha_fin),
        'inventario': lambda: _dinamico_inventario(umbral_stock),
    }

    if tipo not in handlers:
        tipo = 'ventas'

    data = handlers[tipo]()
    return {
        'modo': 'dinamico',
        'tipo': tipo,
        'filtros': {
            'fecha_inicio': fecha_inicio.isoformat(),
            'fecha_fin': fecha_fin.isoformat(),
            'agrupar_por': agrupar_por or data.get('agrupar_por'),
            'umbral_stock': umbral_stock if tipo == 'inventario' else None,
        },
        'totales': data.get('totales', {}),
        'columnas': data.get('columnas', []),
        'filas': data.get('filas', []),
        'series': data.get('series', []),
    }


def _dinamico_ingresos(fecha_inicio, fecha_fin, agrupar_por):
    ingresos = ingresos_confirmados(fecha_inicio, fecha_fin)
    if agrupar_por == 'metodo':
        filas = ingresos['por_metodo']
        columnas = ['metodo_pago', 'cantidad', 'total']
        series = [{'label': row['metodo_pago'], 'value': row['total']} for row in filas]
        usado = 'metodo'
    else:
        filas = ingresos['por_dia']
        columnas = ['fecha', 'total']
        series = [{'label': row['fecha'], 'value': row['total']} for row in filas]
        usado = 'dia'
    return {
        'agrupar_por': usado,
        'totales': {'ingresos_confirmados': ingresos['total'], 'cantidad_pagos': ingresos['cantidad_pagos']},
        'columnas': columnas,
        'filas': filas,
        'series': series,
    }


def _dinamico_ventas(fecha_inicio, fecha_fin, agrupar_por):
    ventas = ventas_reales(fecha_inicio, fecha_fin)
    if agrupar_por == 'estado':
        filas = ventas['por_estado']
        columnas = ['estado', 'cantidad']
        series = [{'label': row['estado'], 'value': row['cantidad']} for row in filas]
        usado = 'estado'
    else:
        filas = ventas['por_producto']
        columnas = ['producto_id', 'producto', 'cantidad', 'total']
        series = [{'label': row['producto'], 'value': row['total']} for row in filas]
        usado = 'producto'
    return {
        'agrupar_por': usado,
        'totales': {'cantidad_pedidos': ventas['cantidad_pedidos'], 'total_vendido': ventas['total_vendido']},
        'columnas': columnas,
        'filas': filas,
        'series': series,
    }


def _dinamico_reservas(fecha_inicio, fecha_fin, agrupar_por):
    reservas = resumen_reservas(fecha_inicio, fecha_fin)
    if agrupar_por == 'sala':
        filas = reservas['por_sala']
        columnas = ['sala_id', 'sala', 'cantidad', 'personas']
        series = [{'label': row['sala'], 'value': row['cantidad']} for row in filas]
        usado = 'sala'
    else:
        filas = reservas['por_estado']
        columnas = ['estado', 'cantidad']
        series = [{'label': row['estado'], 'value': row['cantidad']} for row in filas]
        usado = 'estado'
    return {
        'agrupar_por': usado,
        'totales': {'reservas': reservas['total'], 'reservas_activas': reservas['activas']},
        'columnas': columnas,
        'filas': filas,
        'series': series,
    }


def _dinamico_preordenes(fecha_inicio, fecha_fin, agrupar_por):
    preordenes = resumen_preordenes(fecha_inicio, fecha_fin)
    if agrupar_por == 'producto':
        filas = preordenes['productos_demandados']
        columnas = ['producto_id', 'producto', 'cantidad', 'total']
        series = [{'label': row['producto'], 'value': row['cantidad']} for row in filas]
        usado = 'producto'
    else:
        filas = preordenes['por_estado']
        columnas = ['estado', 'cantidad']
        series = [{'label': row['estado'], 'value': row['cantidad']} for row in filas]
        usado = 'estado'
    return {
        'agrupar_por': usado,
        'totales': {
            'preordenes': preordenes['total'],
            'demanda_anticipada': preordenes['demanda_anticipada'],
            'convertidas_a_pedido': preordenes['convertidas_a_pedido'],
            'total_demanda_anticipada': preordenes['total_demanda_anticipada'],
        },
        'columnas': columnas,
        'filas': filas,
        'series': series,
    }


def _dinamico_ocupacion(fecha_inicio, fecha_fin):
    ocupacion = ocupacion_salas(fecha_inicio, fecha_fin)
    filas = ocupacion['por_sala']
    return {
        'agrupar_por': 'sala',
        'totales': {'ocupacion_promedio': ocupacion['promedio_actual']},
        'columnas': [
            'sala_id',
            'sala',
            'mesas_activas',
            'mesas_ocupadas_o_reservadas',
            'reservas_periodo',
            'ocupacion_actual',
            'ocupacion_periodo',
        ],
        'filas': filas,
        'series': [{'label': row['sala'], 'value': row['ocupacion_periodo']} for row in filas],
    }


def _dinamico_inventario(umbral_stock):
    filas = inventario_critico(umbral_stock)
    return {
        'agrupar_por': 'stock',
        'totales': {'productos_criticos': len(filas)},
        'columnas': [
            'producto_id',
            'producto',
            'categoria',
            'stock',
            'stock_reservado',
            'stock_disponible',
            'umbral',
        ],
        'filas': filas,
        'series': [{'label': row['producto'], 'value': row['stock_disponible']} for row in filas],
    }


def interpretar_reporte_voz(texto, params=None):
    params = dict(params or {})
    texto_normalizado = (texto or '').strip().lower()

    tipo = 'ventas'
    agrupar_por = 'producto'

    if any(word in texto_normalizado for word in ['ingreso', 'pago', 'cobro']):
        tipo = 'ingresos'
        agrupar_por = 'dia'
    elif 'reserva' in texto_normalizado:
        tipo = 'reservas'
        agrupar_por = 'estado'
    elif any(word in texto_normalizado for word in ['preorden', 'pre orden', 'anticipada']):
        tipo = 'preordenes'
        agrupar_por = 'estado'
    elif any(word in texto_normalizado for word in ['ocupacion', 'ocupación', 'sala', 'mesa']):
        tipo = 'ocupacion'
        agrupar_por = 'sala'
    elif any(word in texto_normalizado for word in ['inventario', 'stock', 'critico', 'crítico']):
        tipo = 'inventario'
        agrupar_por = 'stock'

    if 'estado' in texto_normalizado:
        agrupar_por = 'estado'
    elif 'producto' in texto_normalizado:
        agrupar_por = 'producto'
    elif 'sala' in texto_normalizado:
        agrupar_por = 'sala'
    elif 'metodo' in texto_normalizado or 'método' in texto_normalizado:
        agrupar_por = 'metodo'
    elif 'dia' in texto_normalizado or 'día' in texto_normalizado:
        agrupar_por = 'dia'

    today = timezone.localdate()
    if 'hoy' in texto_normalizado:
        params['fecha_inicio'] = today.isoformat()
        params['fecha_fin'] = today.isoformat()
    elif 'ayer' in texto_normalizado:
        ayer = today - timedelta(days=1)
        params['fecha_inicio'] = ayer.isoformat()
        params['fecha_fin'] = ayer.isoformat()
    elif 'semana' in texto_normalizado:
        params['fecha_inicio'] = (today - timedelta(days=today.weekday())).isoformat()
        params['fecha_fin'] = today.isoformat()
    elif 'mes' in texto_normalizado:
        params['fecha_inicio'] = today.replace(day=1).isoformat()
        params['fecha_fin'] = today.isoformat()

    params['tipo'] = tipo
    params['agrupar_por'] = agrupar_por
    reporte = reporte_dinamico(params)

    return {
        'modo': 'voz',
        'entrada': {'texto': texto or ''},
        'interpretacion': {
            'tipo': tipo,
            'agrupar_por': agrupar_por,
            'fecha_inicio': reporte['filtros']['fecha_inicio'],
            'fecha_fin': reporte['filtros']['fecha_fin'],
            'confianza': 0.75 if texto_normalizado else 0.25,
        },
        'respuesta': _respuesta_voz(tipo, reporte),
        'reporte': {
            'totales': reporte['totales'],
            'columnas': reporte['columnas'],
            'filas': reporte['filas'],
            'series': reporte['series'],
        },
    }


def _respuesta_voz(tipo, reporte):
    totales = reporte.get('totales', {})
    if tipo == 'ingresos':
        return f"Encontré Bs. {totales.get('ingresos_confirmados', 0)} en pagos exitosos."
    if tipo == 'reservas':
        return f"Encontré {totales.get('reservas', 0)} reservas en el rango solicitado."
    if tipo == 'preordenes':
        return f"Encontré {totales.get('demanda_anticipada', 0)} preórdenes como demanda anticipada."
    if tipo == 'ocupacion':
        return f"La ocupación promedio actual es {totales.get('ocupacion_promedio', 0)}%."
    if tipo == 'inventario':
        return f"Encontré {totales.get('productos_criticos', 0)} productos con stock crítico."
    return f"Encontré {totales.get('cantidad_pedidos', 0)} pedidos como ventas reales."
