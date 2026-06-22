import stripe
import os
from datetime import datetime, time
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.db import transaction
from django.db.utils import OperationalError, ProgrammingError
from django.db.models import Count, Sum
from django.utils.dateparse import parse_date
from django.utils import timezone
from reservas.models import Reserva, SalaTematica, Mesa
from pedidos.models import Preorden, DetallePreorden, Pedido, DetallePedido
from producto.models import Producto
from usuarios.models import Cliente, Bitacora, Usuario
from .models import Pago
from .reportes import interpretar_reporte_voz, reporte_dinamico, reporte_estatico
from reservas.views import JWTAuthentication, IsAuthenticatedJWT, IsEmpleadoOrAdmin
from rest_framework.permissions import BasePermission

class IsEmpleadoAtencionOrAdmin(BasePermission):
    """
    Permiso para empleados de atención y admins.
    Reutiliza el mismo patrón que IsEmpleadoOrAdmin en reservas/views.py.
    NOTA: Usuario es models.Model puro, no tiene .is_authenticated — NO usar esa propiedad.
    JWTAuthentication retorna (user, token) si el token es válido, o None si no hay header.
    Si retorna None, request.user será AnonymousUser y bool(request.user) → False.
    """
    def has_permission(self, request, view):
        return bool(
            request.user and
            hasattr(request.user, 'cod_rol') and
            request.user.cod_rol and
            request.user.cod_rol.cod_rol in ['admin', 'mesero', 'cocinero', 'emp']
        )

class IsAdminUser(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            hasattr(request.user, 'cod_rol') and
            request.user.cod_rol and
            request.user.cod_rol.cod_rol == 'admin'
        )

def _nombre_usuario(usuario):
    return getattr(usuario, 'nombre', None) or 'No registrado'

def _formatear_fecha_hora(dt):
    return timezone.localtime(dt).strftime('%d/%m/%Y %H:%M') if dt else timezone.localtime().strftime('%d/%m/%Y %H:%M')

def _producto_nota(cantidad, nombre, precio, total):
    return {
        'cantidad': cantidad,
        'producto': nombre,
        'precio': f'{float(precio):.2f}',
        'total': f'{float(total):.2f}',
    }

def construir_nota_venta(pago):
    pedido = pago.pedido
    reserva = pago.reserva
    preorden = pago.preorden

    productos = []
    mesa = None
    sala = None
    cliente = None
    mesero = _nombre_usuario(pago.usuario)

    if pedido:
        mesa = pedido.mesa.nombre if pedido.mesa else None
        sala = pedido.sala.nombre if pedido.sala else (pedido.mesa.sala.nombre if pedido.mesa else None)
        mesero = _nombre_usuario(pago.usuario or pedido.usuario)
        for det in pedido.detalles.filter(confirmado=True):
            productos.append(_producto_nota(det.cantidad, det.producto.nombre, det.precio_unitario, det.subtotal))
    elif preorden:
        mesa = preorden.mesa.nombre if preorden.mesa else None
        sala = preorden.sala.nombre if preorden.sala else (preorden.reserva.sala.nombre if preorden.reserva else None)
        cliente_preorden = preorden.cliente or (preorden.reserva.cliente if preorden.reserva else None)
        cliente = _nombre_usuario(cliente_preorden.id_usuario) if cliente_preorden else None
        mesero = _nombre_usuario(preorden.usuario_mesero) if preorden.usuario_mesero else 'Reserva en línea'
        for det in preorden.detalles.all():
            productos.append(_producto_nota(det.cantidad, det.producto.nombre, det.precio_unitario, det.subtotal))
    elif reserva:
        mesa = reserva.mesa.nombre if reserva.mesa else None
        sala = reserva.sala.nombre if reserva.sala else None
        cliente = _nombre_usuario(reserva.cliente.id_usuario) if reserva.cliente else None
        mesero = 'Reserva en línea'

    subtotal = sum(float(item['total']) for item in productos) if productos else float(pago.monto)
    total = float(pago.monto) if pago.monto is not None else subtotal

    return {
        'numeroComprobante': f'NV-{pago.id:06d}',
        'fechaHora': _formatear_fecha_hora(pago.updated_at or pago.created_at),
        'cliente': cliente,
        'mesero': mesero,
        'mesa': mesa or 'Sin mesa',
        'sala': sala or 'Sin sala',
        'productos': productos,
        'subtotal': f'{subtotal:.2f}',
        'total': f'{total:.2f}',
        'metodoPago': pago.get_metodo_pago_display().upper(),
    }

def obtener_url_retorno_cliente(request, path, env_name, default_base):
    frontend_origin = request.data.get('frontend_origin') or request.META.get('HTTP_ORIGIN')
    if frontend_origin and frontend_origin.startswith(('http://', 'https://')):
        return f"{frontend_origin.rstrip('/')}{path}"
    return os.getenv(env_name, f"{default_base}{path}")

def _fecha_o_hoy(valor):
    if not valor:
        return timezone.localdate()
    fecha = parse_date(valor)
    if not fecha:
        raise ValueError('Formato de fecha invalido. Use YYYY-MM-DD.')
    return fecha

def _periodo_cierre(params):
    fecha_inicio = params.get('fecha_inicio')
    fecha_fin = params.get('fecha_fin')
    fecha = params.get('fecha')

    if fecha_inicio or fecha_fin:
        inicio = _fecha_o_hoy(fecha_inicio)
        fin = _fecha_o_hoy(fecha_fin or fecha_inicio)
    else:
        inicio = _fecha_o_hoy(fecha)
        fin = inicio

    if inicio > fin:
        raise ValueError('La fecha de inicio no puede ser mayor a la fecha fin.')

    return inicio, fin

def _query_pagos_cierre(inicio, fin):
    inicio_dt = timezone.make_aware(datetime.combine(inicio, time.min))
    fin_dt = timezone.make_aware(datetime.combine(fin, time.max))

    return Pago.objects.filter(
        estado='exitoso',
        updated_at__gte=inicio_dt,
        updated_at__lte=fin_dt,
    ).defer(
        'caja_cerrada',
        'caja_cerrada_en',
    ).select_related(
        'usuario',
        'pedido',
        'pedido__mesa',
        'pedido__sala',
        'preorden',
        'preorden__cliente',
        'preorden__cliente__id_usuario',
        'preorden__mesa',
        'preorden__sala',
        'reserva',
        'reserva__cliente',
        'reserva__cliente__id_usuario',
        'reserva__mesa',
        'reserva__sala',
    ).order_by('updated_at', 'id')

def _tipo_comprobante(pago):
    if pago.preorden:
        return 'Preorden'
    if pago.reserva:
        return 'Reserva en linea'
    if pago.pedido and pago.pedido.reserva_id:
        return 'Pedido de reserva'
    return 'Pedido presencial'

def _detalle_cierre(pago):
    nota = construir_nota_venta(pago)
    fecha_hora = timezone.localtime(pago.updated_at)
    cliente_o_mesero = nota.get('cliente') or nota.get('mesero') or 'No registrado'
    try:
        caja_cerrada = pago.caja_cerrada
    except (OperationalError, ProgrammingError):
        caja_cerrada = False

    return {
        'id_pago': pago.id,
        'numero_comprobante': nota['numeroComprobante'],
        'fecha': fecha_hora.strftime('%Y-%m-%d'),
        'hora': fecha_hora.strftime('%H:%M'),
        'mesa': nota['mesa'],
        'sala': nota['sala'],
        'cliente_mesero': cliente_o_mesero,
        'tipo': _tipo_comprobante(pago),
        'metodo_pago': pago.get_metodo_pago_display(),
        'metodo_pago_codigo': pago.metodo_pago,
        'total': f'{float(pago.monto):.2f}',
        'caja_cerrada': caja_cerrada,
    }

def construir_cierre_caja(inicio, fin):
    pagos = _query_pagos_cierre(inicio, fin)
    agregados = pagos.values('metodo_pago').annotate(
        total=Sum('monto'),
        cantidad=Count('id'),
    )

    metodos_base = {
        'efectivo': {'metodo': 'Efectivo', 'total': '0.00', 'cantidad': 0},
        'qr': {'metodo': 'QR', 'total': '0.00', 'cantidad': 0},
        'stripe': {'metodo': 'Tarjeta/Stripe', 'total': '0.00', 'cantidad': 0},
    }

    for item in agregados:
        codigo = item['metodo_pago']
        metodos_base[codigo] = {
            'metodo': metodos_base.get(codigo, {}).get('metodo', codigo.title()),
            'total': f'{float(item["total"] or 0):.2f}',
            'cantidad': item['cantidad'],
        }

    total_general = pagos.aggregate(total=Sum('monto'))['total'] or 0
    cantidad_total = pagos.count()

    try:
        caja_cerrada = cantidad_total > 0 and not pagos.filter(caja_cerrada=False).exists()
    except (OperationalError, ProgrammingError):
        caja_cerrada = False

    return {
        'fecha_inicio': inicio.isoformat(),
        'fecha_fin': fin.isoformat(),
        'total_general': f'{float(total_general):.2f}',
        'cantidad_comprobantes': cantidad_total,
        'por_metodo': list(metodos_base.values()),
        'comprobantes': [_detalle_cierre(pago) for pago in pagos],
        'caja_cerrada': caja_cerrada,
    }

class CrearSesionReservaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def post(self, request):
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY') or os.getenv('STRIPE_SECRET')
        data = request.data
        
        if request.user.cod_rol.cod_rol != 'cliente':
            return Response({'error': 'Solo los clientes pueden hacer reservas web'}, status=status.HTTP_403_FORBIDDEN)
            
        try:
            cliente = Cliente.objects.get(id_usuario=request.user)
        except Cliente.DoesNotExist:
            return Response({'error': 'Perfil de cliente no encontrado'}, status=status.HTTP_400_BAD_REQUEST)

        sala_id = data.get('sala')
        mesa_id = data.get('mesa')
        fecha = data.get('fecha')
        hora_inicio = data.get('hora_inicio')
        hora_fin = data.get('hora_fin')
        cantidad_personas = data.get('cantidad_personas')
        productos_req = data.get('productos')

        from datetime import datetime, timedelta
        try:
            fecha_obj = datetime.strptime(fecha, "%Y-%m-%d").date()
        except:
            return Response({'error': 'Formato de fecha inválido'}, status=status.HTTP_400_BAD_REQUEST)

        if fecha_obj < timezone.localdate():
            return Response({'error': 'No puedes reservar en fechas pasadas'}, status=status.HTTP_400_BAD_REQUEST)

        if hora_inicio >= hora_fin:
            return Response({'error': 'Horario inválido'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            hora_inicio_obj = datetime.strptime(hora_inicio, '%H:%M:%S').time()
        except ValueError:
            hora_inicio_obj = datetime.strptime(hora_inicio, '%H:%M').time()

        inicio_reserva = timezone.make_aware(datetime.combine(fecha_obj, hora_inicio_obj))
        if inicio_reserva <= timezone.localtime() + timedelta(hours=3):
            return Response(
                {'error': 'Debes reservar con al menos 3 horas de anticipacion. Selecciona un horario mas tarde para asegurar la disponibilidad de la mesa.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            sala = SalaTematica.objects.get(id=sala_id)
            mesa = Mesa.objects.get(id=mesa_id, sala=sala)
        except (SalaTematica.DoesNotExist, Mesa.DoesNotExist):
            return Response({'error': 'Sala o Mesa no válidas'}, status=status.HTTP_400_BAD_REQUEST)

        if not sala.habilitada:
            return Response({'error': 'La sala está deshabilitada'}, status=status.HTTP_400_BAD_REQUEST)
        if not mesa.activa:
            return Response({'error': 'La mesa no está activa'}, status=status.HTTP_400_BAD_REQUEST)
        if int(cantidad_personas) > mesa.capacidad:
            return Response({'error': 'La cantidad de personas excede la capacidad de la mesa'}, status=status.HTTP_400_BAD_REQUEST)

        cruce = Reserva.objects.filter(
            mesa=mesa,
            fecha=fecha,
            estado__in=['pendiente', 'confirmada', 'en_curso']
        ).filter(
            hora_inicio__lt=hora_fin,
            hora_fin__gt=hora_inicio
        ).exists()

        if cruce:
            return Response({'error': 'La mesa ya está reservada en este horario'}, status=status.HTTP_400_BAD_REQUEST)

        if not productos_req or not isinstance(productos_req, list) or len(productos_req) == 0:
            return Response({'error': 'Debe agregar al menos un producto para la preorden.'}, status=status.HTTP_400_BAD_REQUEST)

        total_preorden = 0
        detalles_pre = []
        for prod in productos_req:
            try:
                producto = Producto.objects.get(id=prod.get('id'))
            except Producto.DoesNotExist:
                return Response({'error': f'Producto con id {prod.get("id")} no encontrado'}, status=status.HTTP_400_BAD_REQUEST)
            
            cantidad = int(prod.get('cantidad', 0))
            if cantidad <= 0:
                return Response({'error': 'La cantidad debe ser mayor a 0'}, status=status.HTTP_400_BAD_REQUEST)
            if cantidad > producto.stock:
                return Response(
                    {'error': f'Stock insuficiente para el producto "{producto.nombre}": disponible {producto.stock}, solicitado {cantidad}'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            subtotal = producto.precio * cantidad
            total_preorden += subtotal
            detalles_pre.append({
                'producto': producto,
                'cantidad': cantidad,
                'precio_unitario': producto.precio,
                'subtotal': subtotal,
            })

        try:
            with transaction.atomic():
                reserva = Reserva.objects.create(
                    cliente=cliente,
                    sala=sala,
                    mesa=mesa,
                    fecha=fecha,
                    hora_inicio=hora_inicio,
                    hora_fin=hora_fin,
                    cantidad_personas=cantidad_personas,
                    estado='pendiente'
                )

                estado_preorden = 'apartada' if fecha_obj == timezone.localdate() else 'programada'
                preorden = Preorden.objects.create(
                    reserva=reserva,
                    cliente=cliente,
                    sala=sala,
                    mesa=mesa,
                    total=total_preorden,
                    estado=estado_preorden,
                )

                for d in detalles_pre:
                    DetallePreorden.objects.create(
                        preorden=preorden,
                        producto=d['producto'],
                        cantidad=d['cantidad'],
                        precio_unitario=d['precio_unitario'],
                        subtotal=d['subtotal'],
                    )

                pago = Pago.objects.create(
                    reserva=reserva,
                    preorden=preorden,
                    monto=total_preorden,
                    metodo_pago='stripe',
                    estado='pendiente'
                )

                success_url = obtener_url_retorno_cliente(
                    request,
                    '/cliente/mis-reservas',
                    'STRIPE_SUCCESS_URL',
                    'http://localhost:5173'
                )
                cancel_url = obtener_url_retorno_cliente(
                    request,
                    '/cliente/salas',
                    'STRIPE_CANCEL_URL',
                    'http://localhost:5173'
                )
                
                success_url += "?pago_success=true&session_id={CHECKOUT_SESSION_ID}"
                cancel_url += f"?pago_cancel=true&reserva_id={reserva.id}"

                line_items = []
                for d in detalles_pre:
                    line_items.append({
                        'price_data': {
                            'currency': 'bob',
                            'product_data': {
                                'name': d['producto'].nombre,
                            },
                            'unit_amount': int(d['precio_unitario'] * 100),
                        },
                        'quantity': d['cantidad'],
                    })

                session = stripe.checkout.Session.create(
                    payment_method_types=['card'],
                    line_items=line_items,
                    mode='payment',
                    success_url=success_url,
                    cancel_url=cancel_url,
                    metadata={
                        'reserva_id': reserva.id,
                        'preorden_id': preorden.id,
                        'pago_id': pago.id,
                    }
                )

                pago.stripe_session_id = session.id
                pago.save()

                Bitacora.objects.create(
                    usuario=request.user,
                    accion='crear reserva con preorden pago pendiente',
                    detalles=f'Reserva ID {reserva.id}, Preorden ID {preorden.id}, Pago ID {pago.id}'
                )

                return Response({
                    'session_id': session.id,
                    'url': session.url,
                    'checkout_url': session.url,
                    'session_url': session.url,
                    'reserva_id': reserva.id,
                    'estado': 'pendiente'
                }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({'error': f'Error al iniciar el pago: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IniciarPagoPedidoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def post(self, request):
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY') or os.getenv('STRIPE_SECRET')
        data = request.data
        pedido_id = data.get('pedido_id') or data.get('id_pedido')
        reserva_id = data.get('reserva_id')
        preorden_id = data.get('preorden_id')
        
        sala_id = data.get('sala_id')
        mesa_id = data.get('mesa_id')
        productos_req = data.get('productos', [])
        metodo_pago = data.get('metodo_pago')

        if metodo_pago not in ['stripe', 'qr']:
            return Response({'error': 'metodo_pago inválido'}, status=status.HTTP_400_BAD_REQUEST)

        if metodo_pago == 'stripe' and not stripe.api_key:
            return Response({'error': 'La clave secreta de Stripe no está configurada.'}, status=status.HTTP_400_BAD_REQUEST)

        pedido = None
        reserva = None
        preorden = None
        total = 0
        line_items = []

        try:
            if pedido_id:
                try:
                    pedido = Pedido.objects.get(id=pedido_id)
                except Pedido.DoesNotExist:
                    return Response({'error': 'Pedido no encontrado'}, status=status.HTTP_400_BAD_REQUEST)
                
                total = pedido.total
                if total <= 0:
                    return Response({'error': 'El total del pedido debe ser mayor a 0'}, status=status.HTTP_400_BAD_REQUEST)
                
                if Pago.objects.filter(pedido=pedido, estado='exitoso').exists():
                    return Response({'error': 'El pedido ya fue pagado con éxito.'}, status=status.HTTP_400_BAD_REQUEST)

                for det in pedido.detalles.all():
                    line_items.append({
                        'price_data': {
                            'currency': 'bob',
                            'product_data': {
                                'name': det.producto.nombre,
                            },
                            'unit_amount': int(det.precio_unitario * 100),
                        },
                        'quantity': det.cantidad,
                    })
                if not line_items:
                    line_items.append({
                        'price_data': {
                            'currency': 'bob',
                            'product_data': {
                                'name': f"Pago Pedido #{pedido.id}",
                            },
                            'unit_amount': int(total * 100),
                        },
                        'quantity': 1,
                    })

            elif reserva_id:
                try:
                    reserva = Reserva.objects.get(id=reserva_id)
                except Reserva.DoesNotExist:
                    return Response({'error': 'Reserva no encontrada'}, status=status.HTTP_400_BAD_REQUEST)
                
                if Pago.objects.filter(reserva=reserva, estado='exitoso').exists():
                    return Response({'error': 'La reserva ya fue pagada con éxito.'}, status=status.HTTP_400_BAD_REQUEST)
                
                preorden = Preorden.objects.filter(reserva=reserva).first()
                if preorden:
                    total = preorden.total
                    for det in preorden.detalles.all():
                        line_items.append({
                            'price_data': {
                                'currency': 'bob',
                                'product_data': {
                                    'name': det.producto.nombre,
                                },
                                'unit_amount': int(det.precio_unitario * 100),
                            },
                            'quantity': det.cantidad,
                        })
                else:
                    total = 0
                    line_items.append({
                        'price_data': {
                            'currency': 'bob',
                            'product_data': {
                                'name': f"Reserva Sala #{reserva.id}",
                            },
                            'unit_amount': 0,
                        },
                        'quantity': 1,
                    })

            elif preorden_id:
                try:
                    preorden = Preorden.objects.get(id=preorden_id)
                except Preorden.DoesNotExist:
                    return Response({'error': 'Preorden no encontrada'}, status=status.HTTP_400_BAD_REQUEST)
                
                reserva = preorden.reserva
                total = preorden.total
                if Pago.objects.filter(preorden=preorden, estado='exitoso').exists():
                    return Response({'error': 'La preorden ya fue pagada con éxito.'}, status=status.HTTP_400_BAD_REQUEST)
                
                for det in preorden.detalles.all():
                    line_items.append({
                        'price_data': {
                            'currency': 'bob',
                            'product_data': {
                                'name': det.producto.nombre,
                            },
                            'unit_amount': int(det.precio_unitario * 100),
                        },
                        'quantity': det.cantidad,
                    })

            else:
                if not sala_id or not mesa_id:
                    return Response({'error': 'pedido_id, reserva_id, preorden_id o (sala_id y mesa_id) son requeridos'}, status=status.HTTP_400_BAD_REQUEST)
                if not productos_req:
                    return Response({'error': 'Debe incluir al menos un producto'}, status=status.HTTP_400_BAD_REQUEST)

                try:
                    sala = SalaTematica.objects.get(id=sala_id)
                    mesa = Mesa.objects.get(id=mesa_id, sala=sala)
                except (SalaTematica.DoesNotExist, Mesa.DoesNotExist):
                    return Response({'error': 'Sala o Mesa no válidas'}, status=status.HTTP_400_BAD_REQUEST)

                with transaction.atomic():
                    total = 0
                    detalles_preparados = []

                    for prod_data in productos_req:
                        try:
                            producto = Producto.objects.select_for_update().get(id=prod_data.get('id'))
                        except Producto.DoesNotExist:
                            raise ValueError(f'Producto id={prod_data.get("id")} no encontrado')

                        cantidad = int(prod_data.get('cantidad', 0))
                        if cantidad <= 0:
                            raise ValueError('La cantidad debe ser mayor a 0')
                        if producto.stock < cantidad:
                            raise ValueError(
                                f'Stock insuficiente para "{producto.nombre}": '
                                f'disponible {producto.stock}, solicitado {cantidad}'
                            )

                        subtotal = producto.precio * cantidad
                        total += subtotal
                        detalles_preparados.append({
                            'producto': producto,
                            'cantidad': cantidad,
                            'precio_unitario': producto.precio,
                            'subtotal': subtotal,
                        })

                    pedido = Pedido.objects.create(
                        sala=sala,
                        mesa=mesa,
                        usuario=request.user,
                        total=total,
                        estado='pendiente',
                    )

                    for d in detalles_preparados:
                        DetallePedido.objects.create(
                            pedido=pedido,
                            producto=d['producto'],
                            cantidad=d['cantidad'],
                            precio_unitario=d['precio_unitario'],
                            subtotal=d['subtotal'],
                        )
                        p = d['producto']
                        p.stock -= d['cantidad']
                        p.save()

                    mesa.estado = 'ocupada'
                    mesa.save()

                    for d in detalles_preparados:
                        line_items.append({
                            'price_data': {
                                'currency': 'bob',
                                'product_data': {
                                    'name': d['producto'].nombre,
                                },
                                'unit_amount': int(d['precio_unitario'] * 100),
                            },
                            'quantity': d['cantidad'],
                        })

            with transaction.atomic():
                pago = None
                if pedido:
                    pago = Pago.objects.filter(pedido=pedido, estado='pendiente', metodo_pago=metodo_pago).first()
                elif reserva:
                    pago = Pago.objects.filter(reserva=reserva, estado='pendiente', metodo_pago=metodo_pago).first()
                elif preorden:
                    pago = Pago.objects.filter(preorden=preorden, estado='pendiente', metodo_pago=metodo_pago).first()

                if not pago:
                    pago = Pago.objects.create(
                        pedido=pedido,
                        reserva=reserva,
                        preorden=preorden,
                        monto=total,
                        metodo_pago=metodo_pago,
                        estado='pendiente'
                    )

                if metodo_pago == 'stripe':
                    base_success = os.getenv('STRIPE_EMPLOYEE_SUCCESS_URL', 'http://localhost:5173/empleado')
                    base_cancel = os.getenv('STRIPE_EMPLOYEE_CANCEL_URL', 'http://localhost:5173/empleado')
                    success_url = base_success + "?pago_success=true&session_id={CHECKOUT_SESSION_ID}"
                    
                    if pedido:
                        cancel_url = base_cancel + f"?pago_cancel=true&pedido_id={pedido.id}"
                    elif reserva:
                        cancel_url = base_cancel + f"?pago_cancel=true&reserva_id={reserva.id}"
                    else:
                        cancel_url = base_cancel + f"?pago_cancel=true&preorden_id={preorden.id}"

                    session_metadata = {
                        'pago_id': pago.id,
                    }
                    if pedido:
                        session_metadata['pedido_id'] = pedido.id
                    if reserva:
                        session_metadata['reserva_id'] = reserva.id
                    if preorden:
                        session_metadata['preorden_id'] = preorden.id

                    session = stripe.checkout.Session.create(
                        payment_method_types=['card'],
                        line_items=line_items,
                        mode='payment',
                        success_url=success_url,
                        cancel_url=cancel_url,
                        metadata=session_metadata
                    )

                    pago.stripe_session_id = session.id
                    pago.save()

                    return Response({
                        'pago_id': pago.id,
                        'pedido_id': pedido.id if pedido else None,
                        'reserva_id': reserva.id if reserva else None,
                        'preorden_id': preorden.id if preorden else None,
                        'total': float(total),
                        'metodo_pago': 'stripe',
                        'url': session.url,
                        'checkout_url': session.url,
                        'session_url': session.url,
                        'estado': 'pendiente'
                    }, status=status.HTTP_201_CREATED)

                else:
                    import urllib.parse
                    target_name = pedido.mesa.nombre if pedido else (reserva.mesa.nombre if reserva else "Mesa")
                    sala_name = pedido.sala.nombre if pedido else (reserva.sala.nombre if reserva else "Sala")
                    desc = f"Pedido ID: {pedido.id}" if pedido else (f"Reserva ID: {reserva.id}" if reserva else f"Preorden ID: {preorden.id}")
                    
                    qr_data = f"Pago de Bs. {total:.2f} para {target_name} ({sala_name}). {desc}"
                    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=300x300&data={urllib.parse.quote(qr_data)}"

                    return Response({
                        'pago_id': pago.id,
                        'pedido_id': pedido.id if pedido else None,
                        'reserva_id': reserva.id if reserva else None,
                        'preorden_id': preorden.id if preorden else None,
                        'total': float(total),
                        'metodo_pago': 'qr',
                        'qr_url': qr_url
                    }, status=status.HTTP_201_CREATED)

        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': f'Error al procesar el pago: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ConfirmarPagoStripeView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def post(self, request):
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY') or os.getenv('STRIPE_SECRET')
        session_id = request.data.get('session_id')
        if not session_id:
            return Response({'error': 'session_id es requerido'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            session = stripe.checkout.Session.retrieve(session_id)
            if session.payment_status == 'paid':
                with transaction.atomic():
                    pago = Pago.objects.select_for_update().get(stripe_session_id=session_id)
                    if pago.estado != 'exitoso':
                        pago.estado = 'exitoso'
                        pago.stripe_payment_intent = session.payment_intent
                        pago.usuario = request.user
                        pago.save()

                        if pago.reserva:
                            reserva = pago.reserva
                            reserva.estado = 'confirmada'
                            reserva.save()
                            reserva.mesa.estado = 'reservada'
                            reserva.mesa.save()
                            
                            if pago.preorden:
                                pre = pago.preorden
                                pre.estado = 'apartada' if reserva.fecha == timezone.localdate() else 'programada'
                                pre.save()

                            Bitacora.objects.create(
                                usuario=request.user,
                                accion='confirmar pago reserva stripe',
                                detalles=f'Pago ID {pago.id} exitoso. Reserva ID {reserva.id} confirmada.'
                            )

                        if pago.pedido:
                            pedido = pago.pedido
                            pedido.estado = 'confirmado'
                            pedido.save()
                            
                            # Liberar mesa si no quedan deudas
                            from pedidos.services import mesa_tiene_deudas_activas
                            tiene_deudas = mesa_tiene_deudas_activas(pedido.mesa, exclude_pedido_id=pedido.id)
                            
                            if not tiene_deudas:
                                pedido.mesa.estado = 'disponible'
                            else:
                                pedido.mesa.estado = 'ocupada'
                            pedido.mesa.save()

                            Bitacora.objects.create(
                                usuario=request.user,
                                accion='confirmar pago pedido stripe',
                                detalles=f'Pago ID {pago.id} exitoso. Pedido ID {pedido.id} confirmado.'
                            )

                        return Response({
                            'mensaje': 'Pago confirmado correctamente',
                            'estado': 'exitoso',
                            'nota_venta': construir_nota_venta(pago),
                        })
                    else:
                        return Response({
                            'mensaje': 'El pago ya había sido procesado',
                            'estado': 'exitoso',
                            'nota_venta': construir_nota_venta(pago),
                        })
            else:
                return Response({'error': 'La sesión de Stripe no está pagada'}, status=status.HTTP_400_BAD_REQUEST)
        except Pago.DoesNotExist:
            return Response({'error': 'Pago no encontrado para esta sesión'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error al confirmar pago: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ConfirmarPagoQRView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def post(self, request):
        pago_id = request.data.get('pago_id')
        if not pago_id:
            return Response({'error': 'pago_id es requerido'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                pago = Pago.objects.select_for_update().get(id=pago_id)
                if pago.estado != 'exitoso':
                    pago.estado = 'exitoso'
                    pago.usuario = request.user
                    pago.save()

                    if pago.pedido:
                        pedido = pago.pedido
                        pedido.estado = 'confirmado'
                        pedido.save()
                        
                        # Liberar mesa si no quedan deudas
                        from pedidos.services import mesa_tiene_deudas_activas
                        tiene_deudas = mesa_tiene_deudas_activas(pedido.mesa, exclude_pedido_id=pedido.id)
                        
                        if not tiene_deudas:
                            pedido.mesa.estado = 'disponible'
                        else:
                            pedido.mesa.estado = 'ocupada'
                        pedido.mesa.save()

                        Bitacora.objects.create(
                            usuario=request.user,
                            accion='confirmar pago qr',
                            detalles=f'Pago ID {pago.id} exitoso para Pedido ID {pedido.id}.'
                        )

                    return Response({
                        'mensaje': 'Pago por QR confirmado correctamente',
                        'estado': 'exitoso',
                        'nota_venta': construir_nota_venta(pago),
                    })
                else:
                    return Response({
                        'mensaje': 'El pago ya había sido procesado',
                        'estado': 'exitoso',
                        'nota_venta': construir_nota_venta(pago),
                    })
        except Pago.DoesNotExist:
            return Response({'error': 'Pago no encontrado'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error al confirmar QR: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class NotaVentaPedidoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def post(self, request):
        pedido_id = request.data.get('pedido_id')
        metodo_pago = request.data.get('metodo_pago')

        if not pedido_id:
            return Response({'error': 'pedido_id es requerido'}, status=status.HTTP_400_BAD_REQUEST)

        pagos = Pago.objects.filter(pedido_id=pedido_id, estado='exitoso').order_by('-updated_at', '-id')
        if metodo_pago:
            pagos = pagos.filter(metodo_pago=str(metodo_pago).lower())

        pago = pagos.first()
        if not pago:
            return Response({'error': 'No existe un pago confirmado para este pedido'}, status=status.HTTP_404_NOT_FOUND)

        return Response({'nota_venta': construir_nota_venta(pago)}, status=status.HTTP_200_OK)

class CierreCajaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def get(self, request):
        try:
            inicio, fin = _periodo_cierre(request.query_params)
            return Response(construir_cierre_caja(inicio, fin), status=status.HTTP_200_OK)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

class CerrarCajaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminUser]

    def post(self, request):
        try:
            inicio, fin = _periodo_cierre(request.data)
            with transaction.atomic():
                pagos = _query_pagos_cierre(inicio, fin).select_for_update()
                total = pagos.count()
                actualizados = pagos.filter(caja_cerrada=False).update(
                    caja_cerrada=True,
                    caja_cerrada_en=timezone.now(),
                )

            return Response({
                'mensaje': 'Caja cerrada correctamente',
                'comprobantes_periodo': total,
                'comprobantes_cerrados': actualizados,
                'cierre': construir_cierre_caja(inicio, fin),
            }, status=status.HTTP_200_OK)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

class CancelarPagoPedidoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def post(self, request):
        pedido_id = request.data.get('pedido_id')
        if not pedido_id:
            return Response({'error': 'pedido_id es requerido'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                pedido = Pedido.objects.select_for_update().get(id=pedido_id)
                if pedido.estado == 'pendiente':
                    pedido.estado = 'cancelado'
                    pedido.save()

                    for det in pedido.detalles.all():
                        producto = det.producto
                        producto.stock += det.cantidad
                        producto.save()

                    if pedido.mesa:
                        from reservas.views import actualizar_estado_mesa
                        actualizar_estado_mesa(pedido.mesa)

                    for pago in Pago.objects.filter(pedido=pedido):
                        pago.estado = 'cancelado'
                        pago.save()

                    Bitacora.objects.create(
                        usuario=request.user,
                        accion='cancelar pago pedido',
                        detalles=f'Pedido ID {pedido_id} cancelado por falta de pago. Stock restaurado.'
                    )

                    return Response({'mensaje': 'Pedido cancelado y stock restaurado correctamente'})
                else:
                    return Response({'error': 'El pedido no está en estado pendiente de pago'}, status=status.HTTP_400_BAD_REQUEST)
        except Pedido.DoesNotExist:
            return Response({'error': 'Pedido no encontrado'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error al cancelar pedido: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CancelarPagoReservaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def post(self, request):
        reserva_id = request.data.get('reserva_id')
        if not reserva_id:
            return Response({'error': 'reserva_id es requerido'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                reserva = Reserva.objects.select_for_update().get(id=reserva_id)
                
                if request.user.cod_rol.cod_rol == 'cliente':
                    try:
                        cliente = Cliente.objects.get(id_usuario=request.user)
                        if reserva.cliente != cliente:
                            return Response({'error': 'No puedes cancelar reservas de otros'}, status=status.HTTP_403_FORBIDDEN)
                    except Cliente.DoesNotExist:
                        return Response({'error': 'Cliente no encontrado'}, status=status.HTTP_403_FORBIDDEN)

                if reserva.estado == 'pendiente':
                    reserva.estado = 'cancelada'
                    reserva.save()

                    from reservas.views import actualizar_estado_mesa
                    actualizar_estado_mesa(reserva.mesa)

                    for pre in Preorden.objects.filter(reserva=reserva):
                        pre.estado = 'cancelada'
                        pre.save()

                    for pago in Pago.objects.filter(reserva=reserva):
                        pago.estado = 'cancelado'
                        pago.save()

                    Bitacora.objects.create(
                        usuario=request.user,
                        accion='cancelar pago reserva',
                        detalles=f'Reserva ID {reserva_id} cancelada tras abortar checkout.'
                    )

                    return Response({'mensaje': 'Reserva y preorden canceladas correctamente'})
                else:
                    return Response({'error': 'La reserva no está en estado pendiente'}, status=status.HTTP_400_BAD_REQUEST)
        except Reserva.DoesNotExist:
            return Response({'error': 'Reserva no encontrada'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Error al cancelar reserva: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ReporteEstaticoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def get(self, request):
        try:
            return Response(reporte_estatico(request.query_params))
        except ValueError:
            return Response(
                {'error': 'Formato de fecha invalido. Use YYYY-MM-DD.'},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ReporteDinamicoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def get(self, request):
        try:
            return Response(reporte_dinamico(request.query_params))
        except ValueError:
            return Response(
                {'error': 'Formato de fecha invalido. Use YYYY-MM-DD.'},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ReporteVozView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def post(self, request):
        texto = request.data.get('texto') or request.data.get('consulta') or ''
        params = {
            'fecha_inicio': request.data.get('fecha_inicio'),
            'fecha_fin': request.data.get('fecha_fin'),
            'umbral_stock': request.data.get('umbral_stock'),
        }
        params = {key: value for key, value in params.items() if value not in [None, '']}

        try:
            return Response(interpretar_reporte_voz(texto, params))
        except ValueError:
            return Response(
                {'error': 'Formato de fecha invalido. Use YYYY-MM-DD.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
