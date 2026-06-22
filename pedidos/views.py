from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from rest_framework.views import APIView
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from decimal import Decimal

from producto.models import Categoria, Producto
from producto.serializers import CategoriaSerializer, ProductoSerializer
from .models import Pedido, DetallePedido, Preorden, DetallePreorden, Notificacion
from .serializers import (
    PedidoSerializer, DetallePedidoSerializer,
    PreordenSerializer, DetallePreordenSerializer,
    CocinaComandaSerializer, CocinaComandaDetailSerializer,
)
from .permissions import IsCocinero
from usuarios.models import Usuario, Cliente, Bitacora
from usuarios.views import decodificar_token
from reservas.models import SalaTematica, Mesa, Reserva
from .services import notificar_pedido_a_cocina, notificar_pedido_listo_al_mesero
from .promociones import recalcular_totales_pedido, total_confirmado_pendiente


def datos_cliente_presencial(data):
    cliente_id = data.get('cliente_id')
    nombre_cliente = (data.get('nombre_cliente') or '').strip()
    if cliente_id:
        try:
            cliente = Cliente.objects.select_related('id_usuario').get(
                id_usuario__id_usuario=cliente_id,
            )
        except Cliente.DoesNotExist:
            raise ValueError('El cliente seleccionado no existe.')
        return cliente, cliente.id_usuario.nombre
    return None, nombre_cliente or 'Cliente presencial'


def serializar_notificacion(notificacion):
    pedido = notificacion.pedido
    return {
        'id': notificacion.id,
        'tipo': notificacion.tipo,
        'titulo': notificacion.titulo,
        'mensaje': notificacion.mensaje,
        'leido': notificacion.leido,
        'fecha': notificacion.fecha_creacion,
        'pedido_id': pedido.id if pedido else None,
        'pedido_estado': pedido.estado if pedido else None,
        'cliente': (
            pedido.reserva.cliente.id_usuario.nombre
            if pedido and pedido.reserva_id
            else pedido.nombre_cliente if pedido else None
        ),
        'sala': pedido.sala.nombre if pedido and pedido.sala else None,
        'mesa': pedido.mesa.nombre if pedido and pedido.mesa else None,
    }


# ---------------------------------------------------------------------------
# Auth compartida (duplicada de reservas.views para evitar import circular)
# ---------------------------------------------------------------------------

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        # DEBUG: imprimir header para depuración rápida
        try:
            print(f"[JWTAuthentication] Authorization header: {auth_header}")
        except Exception:
            pass
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        token = auth_header.split(' ')[1]
        payload = decodificar_token(token)
        try:
            print(f"[JWTAuthentication] Decoded payload: {payload}")
        except Exception:
            pass
        if isinstance(payload, dict) and payload.get('error'):
            raise AuthenticationFailed(payload['error'])
        try:
            user = Usuario.objects.get(id_usuario=payload.get('user_id'))
            return (user, token)
        except Usuario.DoesNotExist:
            raise AuthenticationFailed('Usuario no encontrado')


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.cod_rol.cod_rol == 'admin')


class IsEmpleadoOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.cod_rol.cod_rol in ['admin', 'mesero', 'cocinero', 'emp']
        )


class IsMeseroOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.cod_rol.cod_rol in ['admin', 'mesero']
        )


class IsEmpleadoAtencionOrAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.cod_rol.cod_rol in ['admin', 'mesero', 'emp']
        )
    
class IsMeseroOnly(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.cod_rol.cod_rol == 'mesero'
        )

class IsAuthenticatedJWT(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user)



# ---------------------------------------------------------------------------
# PedidoViewSet
# ---------------------------------------------------------------------------

class PedidoViewSet(viewsets.ModelViewSet):
    queryset = Pedido.objects.select_related(
        'reserva',
        'sala',
        'mesa',
        'usuario',
        'promocion',
    ).prefetch_related('detalles__producto')
    serializer_class = PedidoSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def get_permissions(self):
        if self.action == 'crear_por_mesero':
          return [IsEmpleadoAtencionOrAdmin()]

        if self.action == 'marcar_entregado':
                    return [IsEmpleadoAtencionOrAdmin()]

        if self.action == 'cancelar_pedido':
                    return [IsMeseroOrAdmin()]

        if self.action in ['aplicar_promocion', 'quitar_promocion']:
            return [IsEmpleadoAtencionOrAdmin()]

        return [IsEmpleadoOrAdmin()]

    @action(detail=False, methods=['post'])
    def crear_por_mesero(self, request):
        """
        Mesero crea un pedido directo en una mesa (sin reserva previa).
        Body: { sala_id, mesa_id, productos: [{id, cantidad}] }
        Descuenta stock inmediatamente.
        """
        data = request.data
        sala_id = data.get('sala_id')
        mesa_id = data.get('mesa_id')
        productos_req = data.get('productos', [])
        try:
            cliente, nombre_cliente = datos_cliente_presencial(data)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        if not sala_id or not mesa_id:
            return Response(
                {'error': 'sala_id y mesa_id son requeridos'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not productos_req:
            return Response(
                {'error': 'Debe incluir al menos un producto'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if request.user.cod_rol.cod_rol not in ['admin', 'mesero', 'emp']:
            return Response(
                {'error': 'Solo el empleado o administrador puede crear pedidos directos.'},
                status=status.HTTP_403_FORBIDDEN,
            )

        try:
            sala = SalaTematica.objects.get(id=sala_id)
            mesa = Mesa.objects.get(id=mesa_id, sala=sala)
        except (SalaTematica.DoesNotExist, Mesa.DoesNotExist):
            return Response(
                {'error': 'Sala o Mesa no válidas'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from pedidos.services import obtener_pedido_activo
        if obtener_pedido_activo(mesa):
            return Response(
                {'error': 'La mesa ya tiene un pedido activo.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
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
                    cliente=cliente,
                    nombre_cliente=nombre_cliente,
                    total=total,
                    estado='confirmado',
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

                Bitacora.objects.create(
                    usuario=request.user,
                    accion='crear pedido mesero',
                    detalles=f'Pedido {pedido.id} — Mesa {mesa.nombre}',
                )
                notificar_pedido_a_cocina(pedido)

        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(pedido)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    
    @action(detail=True, methods=['patch'])
    def marcar_entregado(self, request, pk=None):
        """
        CU18 — Mesero marca un pedido como entregado.
        Solo permite: lista → entregada.
        """
        pedido = self.get_object()

        if request.user.cod_rol.cod_rol not in ['admin', 'mesero', 'emp']:
            return Response(
                {'error': 'Solo el empleado o administrador puede marcar pedidos como entregados.'},
                status=status.HTTP_403_FORBIDDEN
            )

        if pedido.estado == 'entregada':
            return Response(
                {'error': 'El pedido ya fue entregado.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if pedido.estado == 'cancelado':
            return Response(
                {'error': 'No se puede entregar un pedido cancelado.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if pedido.estado != 'lista':
            return Response(
                {'error': 'Solo se puede entregar un pedido que esté en estado Lista.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        pedido.estado = 'entregada'
        pedido.save()

        if pedido.mesa:
            pedido.mesa.estado = 'disponible'
            pedido.mesa.save()

        Bitacora.objects.create(
            usuario=request.user,
            accion='marcar pedido entregado',
            detalles=f'Pedido {pedido.id} entregado'
        )

        serializer = self.get_serializer(pedido)

        return Response({
            'mensaje': 'Pedido marcado como entregado.',
            'pedido': serializer.data
        }, status=status.HTTP_200_OK)
    
    @action(detail=True, methods=['patch'])
    def cancelar_pedido(self, request, pk=None):
        """
        CU18 — Mesero cancela un pedido antes de preparación.
        Solo permite: pendiente/confirmado → cancelado.
        """
        pedido = self.get_object()

        if request.user.cod_rol.cod_rol != 'mesero':
            return Response(
                {'error': 'Solo el mesero puede cancelar pedidos.'},
                status=status.HTTP_403_FORBIDDEN
            )

        if pedido.estado == 'cancelado':
            return Response(
                {'error': 'El pedido ya está cancelado.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if pedido.estado in ['en_preparacion', 'lista', 'entregada']:
            return Response(
                {'error': 'No se puede cancelar un pedido que ya está en preparación, listo o entregado.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if pedido.estado not in ['pendiente', 'confirmado']:
            return Response(
                {'error': f'No se puede cancelar un pedido en estado {pedido.estado}.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Solo cambiar estado a 'cancelado' — no tocar stock, mesas, reservas, salas, cocina, ni comanda.
        pedido.estado = 'cancelado'
        pedido.save()

        Bitacora.objects.create(
            usuario=request.user,
            accion='cancelar pedido',
            detalles=f'Pedido {pedido.id} cancelado'
        )

        serializer = self.get_serializer(pedido)

        return Response({
            'mensaje': 'Pedido cancelado correctamente.',
            'pedido': serializer.data
        }, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='aplicar-promocion')
    def aplicar_promocion(self, request, pk=None):
        from finanzas.models import Pago
        from promocion.models import Promocion

        pedido = self.get_object()
        if pedido.estado == 'cancelado':
            return Response(
                {'error': 'No se puede aplicar una promoción a un pedido cancelado.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if Pago.objects.filter(pedido=pedido, estado='exitoso').exists():
            return Response(
                {'error': 'No se puede aplicar una promoción a un pedido pagado.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        codigo = (request.data.get('codigo') or '').strip()
        if not codigo:
            return Response(
                {'error': 'El código de promoción es requerido.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        promocion = Promocion.objects.filter(codigo__iexact=codigo).first()
        if not promocion:
            return Response(
                {'error': 'La promoción especificada no existe.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        if not promocion.activa:
            return Response(
                {'error': 'La promoción no está activa.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        hoy = timezone.localdate()
        if not promocion.fecha_inicio <= hoy <= promocion.fecha_fin:
            return Response(
                {'error': 'La promoción no está vigente para la fecha actual.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            pedido = Pedido.objects.select_for_update().get(pk=pedido.pk)
            pedido.promocion = promocion
            recalcular_totales_pedido(pedido)
            if pedido.descuento <= Decimal('0.00'):
                pedido.promocion = None
                recalcular_totales_pedido(pedido)
                return Response(
                    {'error': 'La promoción no aplica a los productos del pedido.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            Bitacora.objects.create(
                usuario=request.user,
                accion='aplicar promocion pedido',
                detalles=f'Promoción {promocion.codigo} aplicada al pedido {pedido.id}.',
            )

        return Response(self.get_serializer(pedido).data)

    @action(detail=True, methods=['post'], url_path='quitar-promocion')
    def quitar_promocion(self, request, pk=None):
        from finanzas.models import Pago

        pedido = self.get_object()
        if pedido.estado == 'cancelado':
            return Response(
                {'error': 'No se puede modificar un pedido cancelado.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if Pago.objects.filter(pedido=pedido, estado='exitoso').exists():
            return Response(
                {'error': 'No se puede modificar un pedido pagado.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            pedido = Pedido.objects.select_for_update().get(pk=pedido.pk)
            pedido.promocion = None
            recalcular_totales_pedido(pedido)
            Bitacora.objects.create(
                usuario=request.user,
                accion='quitar promocion pedido',
                detalles=f'Promoción retirada del pedido {pedido.id}.',
            )

        return Response(self.get_serializer(pedido).data)

# ---------------------------------------------------------------------------
# PreordenViewSet
# ---------------------------------------------------------------------------

class PreordenViewSet(viewsets.ModelViewSet):
    serializer_class = PreordenSerializer
    authentication_classes = [JWTAuthentication]

    def get_queryset(self):
        return (
            Preorden.objects
            .select_related('reserva', 'cliente__id_usuario', 'sala', 'mesa', 'usuario_mesero')
            .prefetch_related('detalles__producto')
        )

    def get_permissions(self):
        if self.action == 'crear_por_cliente':
            return [IsAuthenticatedJWT()]
        if self.action in ['list', 'retrieve', 'hoy',
                            'marcar_con_pedido', 'marcar_entregada', 'cancelar']:
            return [IsEmpleadoOrAdmin()]
        return [IsAdmin()]

    # ------------------------------------------------------------------
    # GET /api/preordenes/hoy/
    # ------------------------------------------------------------------
    @action(detail=False, methods=['get'])
    def hoy(self, request):
        """Preórdenes cuya reserva es para el día de hoy (excluye canceladas)."""
        today = timezone.localdate()
        qs = self.get_queryset().filter(
            reserva__fecha=today
        ).exclude(estado='cancelada')
        serializer = self.get_serializer(qs, many=True, context={'request': request})
        return Response(serializer.data)

    # ------------------------------------------------------------------
    # POST /api/preordenes/crear_por_cliente/
    # ------------------------------------------------------------------
    @action(detail=False, methods=['post'])
    def crear_por_cliente(self, request):
        """
        Cliente crea una preorden para una reserva existente.
        Body: { reserva_id, productos: [{id, cantidad}], notas }
        NO descuenta stock.
        """
        data = request.data
        reserva_id = data.get('reserva_id')
        productos_req = data.get('productos', [])
        notas = data.get('notas', '')

        if not reserva_id:
            return Response(
                {'error': 'reserva_id es requerido'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not productos_req:
            return Response(
                {'error': 'Debe incluir al menos un producto'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            reserva = Reserva.objects.get(id=reserva_id)
        except Reserva.DoesNotExist:
            return Response(
                {'error': 'Reserva no encontrada'},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Verificar titularidad
        if request.user.cod_rol.cod_rol == 'cliente':
            try:
                cliente = Cliente.objects.get(id_usuario=request.user)
            except Cliente.DoesNotExist:
                return Response(
                    {'error': 'Perfil de cliente no encontrado'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if reserva.cliente != cliente:
                return Response(
                    {'error': 'No puedes crear una preorden para la reserva de otro cliente'},
                    status=status.HTTP_403_FORBIDDEN,
                )
        else:
            cliente = reserva.cliente

        if Preorden.objects.filter(reserva=reserva).exists():
            return Response(
                {'error': 'Esta reserva ya tiene una preorden asociada'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if reserva.estado not in ['pendiente', 'confirmada']:
            return Response(
                {'error': f'No se puede agregar preorden a una reserva en estado "{reserva.estado}"'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        estado_preorden = 'apartada' if reserva.fecha == timezone.localdate() else 'programada'

        total = 0
        detalles_preparados = []
        for prod_data in productos_req:
            try:
                producto = Producto.objects.get(id=prod_data.get('id'))
            except Producto.DoesNotExist:
                return Response(
                    {'error': f'Producto id={prod_data.get("id")} no encontrado'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            cantidad = int(prod_data.get('cantidad', 0))
            if cantidad <= 0:
                return Response(
                    {'error': 'La cantidad debe ser mayor a 0'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if cantidad > producto.stock:
                return Response(
                    {'error': f'Stock insuficiente para el producto "{producto.nombre}": disponible {producto.stock}, solicitado {cantidad}'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            subtotal = producto.precio * cantidad
            total += subtotal
            detalles_preparados.append({
                'producto': producto,
                'cantidad': cantidad,
                'precio_unitario': producto.precio,
                'subtotal': subtotal,
            })

        preorden = Preorden.objects.create(
            reserva=reserva,
            cliente=cliente,
            sala=reserva.sala,
            mesa=reserva.mesa,
            total=total,
            estado=estado_preorden,
            notas=notas,
        )
        for d in detalles_preparados:
            DetallePreorden.objects.create(
                preorden=preorden,
                producto=d['producto'],
                cantidad=d['cantidad'],
                precio_unitario=d['precio_unitario'],
                subtotal=d['subtotal'],
            )

        Bitacora.objects.create(
            usuario=request.user,
            accion='crear preorden cliente',
            detalles=f'Preorden {preorden.id} — Reserva {reserva.id}',
        )

        serializer = self.get_serializer(preorden, context={'request': request})
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    # ------------------------------------------------------------------
    # PATCH /api/preordenes/{id}/marcar_con_pedido/
    # ------------------------------------------------------------------
    @action(detail=True, methods=['patch'])
    def marcar_con_pedido(self, request, pk=None):
        preorden = self.get_object()
        if preorden.estado in ['cancelada', 'entregada']:
            return Response(
                {'error': f'No se puede cambiar estado desde "{preorden.estado}"'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        preorden.estado = 'con_pedido'
        preorden.save()
        return Response({'mensaje': 'Preorden marcada como con_pedido', 'estado': preorden.estado})

    # ------------------------------------------------------------------
    # PATCH /api/preordenes/{id}/marcar_entregada/
    # ------------------------------------------------------------------
    @action(detail=True, methods=['patch'])
    def marcar_entregada(self, request, pk=None):
        preorden = self.get_object()
        if preorden.estado == 'cancelada':
            return Response(
                {'error': 'No se puede marcar como entregada una preorden cancelada'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        preorden.estado = 'entregada'
        preorden.save()
        return Response({'mensaje': 'Preorden marcada como entregada', 'estado': preorden.estado})

    # ------------------------------------------------------------------
    # PATCH /api/preordenes/{id}/cancelar/
    # ------------------------------------------------------------------
    @action(detail=True, methods=['patch'])
    def cancelar(self, request, pk=None):
        preorden = self.get_object()
        if preorden.estado in ['con_pedido', 'entregada']:
            return Response(
                {'error': f'No se puede cancelar una preorden en estado "{preorden.estado}"'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if preorden.estado == 'cancelada':
            return Response(
                {'error': 'La preorden ya está cancelada'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        preorden.estado = 'cancelada'
        preorden.save()
        Bitacora.objects.create(
            usuario=request.user,
            accion='cancelar preorden manual',
            detalles=f'Preorden {preorden.id} cancelada manualmente',
        )
        return Response({'mensaje': 'Preorden cancelada', 'estado': preorden.estado})


class CocinaPerfilView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsCocinero]

    def get(self, request):
        usuario = request.user
        cliente = getattr(usuario, 'cliente', None)

        data = {
            'id': usuario.id_usuario,
            'nombre': usuario.nombre,
            'correo': usuario.correo,
            'telefono': cliente.telefono if cliente else None,
            'direccion': cliente.direccion if cliente else None,
            'rol': 'Cocinero',
        }
        return Response(data)


class CocinaComandasView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsCocinero]

    def get(self, request):
        pedidos = Pedido.objects.filter(
            estado__in=['pendiente', 'confirmado', 'en_preparacion', 'lista']
        ).select_related(
            'reserva__cliente__id_usuario',
            'reserva__sala',
            'reserva__mesa',
            'cliente__id_usuario',
            'sala',
            'mesa',
            'usuario__cod_rol',
        ).prefetch_related('detalles__producto')

        serializer = CocinaComandaSerializer(pedidos, many=True, context={'request': request})
        return Response(serializer.data)


class CocinaComandaDetailView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsCocinero]

    def get(self, request, id):
        pedido = get_object_or_404(
            Pedido.objects.filter(estado__in=['pendiente', 'confirmado', 'en_preparacion', 'lista'])
            .select_related(
                'reserva__cliente__id_usuario',
                'reserva__sala',
                'reserva__mesa',
                'cliente__id_usuario',
                'sala',
                'mesa',
                'usuario__cod_rol',
            ).prefetch_related('detalles__producto'),
            id=id,
        )
        serializer = CocinaComandaDetailSerializer(pedido, context={'request': request})
        return Response(serializer.data)


class CocinaComandaEnPreparacionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsCocinero]

    def patch(self, request, id):
        pedido = get_object_or_404(Pedido, id=id)
        if pedido.estado not in ['pendiente', 'confirmado']:
            return Response(
                {'error': 'Solo se puede pasar a En preparación desde Pendiente o Confirmado.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        pedido.estado = 'en_preparacion'
        pedido.save()
        serializer = CocinaComandaDetailSerializer(pedido, context={'request': request})
        return Response(serializer.data)


class CocinaComandaListaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsCocinero]

    def patch(self, request, id):
        pedido = get_object_or_404(Pedido, id=id)
        if pedido.estado != 'en_preparacion':
            return Response(
                {'error': 'Solo se puede marcar como Lista desde el estado En preparación.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        pedido.estado = 'lista'
        pedido.save()

        mensaje = 'Comanda marcada como Lista.'
        notificacion_creada = notificar_pedido_listo_al_mesero(pedido)
        if notificacion_creada is True:
            mensaje += ' Notificación enviada al mesero responsable.'
        elif notificacion_creada is False:
            mensaje += ' El mesero responsable ya estaba notificado.'
        else:
            mensaje += ' No se encontró un mesero responsable para notificar.'

        serializer = CocinaComandaDetailSerializer(pedido, context={'request': request})
        return Response({'message': mensaje, 'pedido': serializer.data})


class PedidoActivoMesaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def get(self, request, mesa_id):
        from pedidos.services import obtener_pedido_activo
        mesa = get_object_or_404(Mesa, id=mesa_id)
        pedido = obtener_pedido_activo(mesa)

        if not pedido:
            return Response({'error': 'No hay pedido activo para esta mesa'}, status=status.HTTP_404_NOT_FOUND)

        serializer = PedidoSerializer(pedido, context={'request': request})
        return Response(serializer.data)


class IniciarPedidoMesaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def post(self, request, mesa_id):
        mesa = get_object_or_404(Mesa, id=mesa_id)
        try:
            cliente, nombre_cliente = datos_cliente_presencial(request.data)
        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        with transaction.atomic():
            from pedidos.services import obtener_pedido_activo
            pedido = obtener_pedido_activo(mesa)

            if pedido:
                pedido = Pedido.objects.select_for_update().get(id=pedido.id)
                if pedido.estado == 'pendiente' and not pedido.detalles.exists():
                    pedido.cliente = cliente
                    pedido.nombre_cliente = nombre_cliente
                    pedido.save(update_fields=['cliente', 'nombre_cliente'])
            else:
                # If the mesa is disponible, transition it to occupied
                if mesa.estado == 'disponible':
                    reserva_futura = Reserva.objects.filter(
                        mesa=mesa,
                        fecha=timezone.localdate(),
                        estado__in=['pendiente', 'confirmada']
                    ).exists()
                    if reserva_futura:
                        return Response({'error': 'La mesa tiene una reserva activa para hoy y no puede ocuparse libremente'}, status=status.HTTP_400_BAD_REQUEST)
                    mesa.estado = 'ocupada'
                    mesa.save()

                pedido = Pedido.objects.create(
                    sala=mesa.sala,
                    mesa=mesa,
                    usuario=request.user,
                    cliente=cliente,
                    nombre_cliente=nombre_cliente,
                    total=0.00,
                    estado='pendiente'
                )
                Bitacora.objects.create(
                    usuario=request.user,
                    accion='iniciar pedido mesa',
                    detalles=f'Pedido {pedido.id} iniciado para mesa {mesa.nombre}'
                )

            serializer = PedidoSerializer(pedido, context={'request': request})
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class AgregarDetallePedidoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def post(self, request, pedido_id):
        pedido = get_object_or_404(Pedido, id=pedido_id)
        if pedido.estado not in ['pendiente', 'confirmado']:
            return Response({'error': f'No se pueden agregar productos a un pedido en estado {pedido.estado}'}, status=status.HTTP_400_BAD_REQUEST)

        producto_id = request.data.get('producto_id')
        cantidad = int(request.data.get('cantidad', 1))
        observaciones = request.data.get('observaciones', '')

        if cantidad <= 0:
            return Response({'error': 'La cantidad debe ser mayor a 0'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            pedido = Pedido.objects.select_for_update().get(id=pedido_id)
            producto = Producto.objects.select_for_update().get(id=producto_id)

            if producto.stock < cantidad:
                return Response({
                    'error': f'Stock insuficiente para "{producto.nombre}": disponible {producto.stock}, solicitado {cantidad}'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Decrement stock
            producto.stock -= cantidad
            producto.save()

            # Check if detail already exists
            detalle = DetallePedido.objects.filter(pedido=pedido, producto=producto).first()
            if detalle:
                detalle.cantidad += cantidad
                detalle.subtotal = detalle.cantidad * detalle.precio_unitario
                if observaciones:
                    detalle.observaciones = (detalle.observaciones or '') + '\n' + observaciones
                detalle.save()
            else:
                detalle = DetallePedido.objects.create(
                    pedido=pedido,
                    producto=producto,
                    cantidad=cantidad,
                    precio_unitario=producto.precio,
                    subtotal=producto.precio * cantidad,
                    observaciones=observaciones
                )

            recalcular_totales_pedido(pedido)

            serializer = PedidoSerializer(pedido, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)


class ActualizarEliminarDetallePedidoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def patch(self, request, pedido_id, detalle_id):
        pedido = get_object_or_404(Pedido, id=pedido_id)
        if pedido.estado not in ['pendiente', 'confirmado']:
            return Response({'error': f'No se pueden modificar productos en un pedido en estado {pedido.estado}'}, status=status.HTTP_400_BAD_REQUEST)

        detalle = get_object_or_404(DetallePedido, id=detalle_id, pedido=pedido)
        nueva_cantidad = request.data.get('cantidad')
        observaciones = request.data.get('observaciones')

        with transaction.atomic():
            pedido = Pedido.objects.select_for_update().get(id=pedido_id)
            detalle = DetallePedido.objects.select_for_update().get(id=detalle_id)
            producto = Producto.objects.select_for_update().get(id=detalle.producto.id)

            if nueva_cantidad is not None:
                nueva_cantidad = int(nueva_cantidad)
                if nueva_cantidad <= 0:
                    return Response({'error': 'La cantidad debe ser mayor a 0. Use DELETE para remover el producto.'}, status=status.HTTP_400_BAD_REQUEST)

                diferencia = nueva_cantidad - detalle.cantidad
                if diferencia > 0:
                    if producto.stock < diferencia:
                        return Response({
                            'error': f'Stock insuficiente para "{producto.nombre}": disponible {producto.stock}, solicitado incremento de {diferencia}'
                        }, status=status.HTTP_400_BAD_REQUEST)
                    producto.stock -= diferencia
                elif diferencia < 0:
                    producto.stock += abs(diferencia)

                producto.save()
                detalle.cantidad = nueva_cantidad
                detalle.subtotal = nueva_cantidad * detalle.precio_unitario

            if observaciones is not None:
                detalle.observaciones = observaciones

            detalle.save()

            recalcular_totales_pedido(pedido)

            serializer = PedidoSerializer(pedido, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, pedido_id, detalle_id):
        pedido = get_object_or_404(Pedido, id=pedido_id)
        if pedido.estado not in ['pendiente', 'confirmado']:
            return Response({'error': f'No se pueden eliminar productos de un pedido en estado {pedido.estado}'}, status=status.HTTP_400_BAD_REQUEST)

        detalle = get_object_or_404(DetallePedido, id=detalle_id, pedido=pedido)

        with transaction.atomic():
            pedido = Pedido.objects.select_for_update().get(id=pedido_id)
            detalle = DetallePedido.objects.select_for_update().get(id=detalle_id)
            producto = Producto.objects.select_for_update().get(id=detalle.producto.id)

            # Restore stock
            producto.stock += detalle.cantidad
            producto.save()

            # Delete detail
            detalle.delete()

            recalcular_totales_pedido(pedido)

            serializer = PedidoSerializer(pedido, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)


class ConfirmarPedidoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def post(self, request, id):
        from django.db.models import Sum
        pedido = get_object_or_404(Pedido, id=id)
        if pedido.estado not in ['pendiente', 'confirmado']:
            return Response({'error': f'No se puede confirmar un pedido en estado {pedido.estado}'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            pedido = Pedido.objects.select_for_update().get(id=id)
            detalles_pendientes = pedido.detalles.filter(confirmado=False)
            
            from finanzas.models import Pago
            if not detalles_pendientes.exists():
                notificar_pedido_a_cocina(pedido)
                serializer = PedidoSerializer(pedido, context={'request': request})
                return Response(serializer.data, status=status.HTTP_200_OK)

            # Update unconfirmed details to confirmed
            now = timezone.now()
            for det in detalles_pendientes:
                det.confirmado = True
                det.fecha_confirmacion = now
                det.usuario_confirmacion = request.user
                det.save()

            if pedido.estado == 'pendiente':
                pedido.estado = 'confirmado'
                pedido.save()

            if pedido.mesa:
                pedido.mesa.estado = 'ocupada'
                pedido.mesa.save()

            Bitacora.objects.create(
                usuario=request.user,
                accion='confirmar pedido',
                detalles=f'Pedido ID {pedido.id} confirmado por mesero.'
            )
            notificar_pedido_a_cocina(pedido)

            serializer = PedidoSerializer(pedido, context={'request': request})
            return Response(serializer.data, status=status.HTTP_200_OK)


class ClientesPedidoBuscarView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoAtencionOrAdmin]

    def get(self, request):
        termino = request.query_params.get('q', '').strip()
        clientes = Cliente.objects.select_related('id_usuario').order_by('id_usuario__nombre')
        if termino:
            from django.db.models import Q
            clientes = clientes.filter(
                Q(id_usuario__nombre__icontains=termino)
                | Q(id_usuario__correo__icontains=termino)
            )
        return Response([
            {
                'id': cliente.id_usuario.id_usuario,
                'nombre': cliente.id_usuario.nombre,
                'correo': cliente.id_usuario.correo,
            }
            for cliente in clientes[:10]
        ])


class NotificacionesOperativasView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def get(self, request):
        try:
            limite = min(max(int(request.query_params.get('limite', 10)), 1), 50)
        except (TypeError, ValueError):
            limite = 10
        notificaciones = (
            Notificacion.objects.filter(usuario_destino=request.user)
            .select_related(
                'pedido__sala',
                'pedido__mesa',
                'pedido__cliente__id_usuario',
                'pedido__reserva__cliente__id_usuario',
            )
            .order_by('-fecha_creacion')[:limite]
        )
        return Response({
            'results': [serializar_notificacion(n) for n in notificaciones],
            'no_leidas': Notificacion.objects.filter(
                usuario_destino=request.user,
                leido=False,
            ).count(),
        })


class NotificacionOperativaLeidaView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticatedJWT]

    def patch(self, request, pk):
        notificacion = get_object_or_404(
            Notificacion,
            id=pk,
            usuario_destino=request.user,
        )
        if not notificacion.leido:
            notificacion.leido = True
            notificacion.save(update_fields=['leido'])
        return Response(serializar_notificacion(notificacion))


class ResumenPagoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def get(self, request, id):
        from django.db.models import Sum
        from finanzas.models import Pago
        pedido = get_object_or_404(Pedido, id=id)
        
        # Calculate totals
        total = pedido.total
        total_pagado = (
            Pago.objects.filter(pedido=pedido, estado='exitoso')
            .aggregate(Sum('monto'))['monto__sum']
            or Decimal('0.00')
        )
        total_pendiente = total_confirmado_pendiente(pedido, total_pagado)

        productos_confirmados = DetallePedidoSerializer(pedido.detalles.filter(confirmado=True), many=True).data
        productos_pendientes = DetallePedidoSerializer(pedido.detalles.filter(confirmado=False), many=True).data
        
        has_pending = pedido.detalles.filter(confirmado=False).exists()
        
        puede_pagar = True
        motivo_bloqueo_pago = None
        
        if len(pedido.detalles.all()) == 0:
            puede_pagar = False
            motivo_bloqueo_pago = "El pedido está vacío"
        elif has_pending:
            puede_pagar = False
            motivo_bloqueo_pago = "Confirma los productos pendientes antes de realizar el pago"
        elif total_pendiente <= Decimal('0.00'):
            puede_pagar = False
            motivo_bloqueo_pago = "El pedido ya está totalmente pagado"

        return Response({
            "pedido_id": pedido.id,
            "mesa": pedido.mesa.nombre if pedido.mesa else None,
            "sala": pedido.sala.nombre if pedido.sala else (pedido.mesa.sala.nombre if pedido.mesa else None),
            "estado_pedido": pedido.estado,
            "estado_pago": "PAGADO" if total_pendiente <= Decimal('0.00') and not has_pending and len(pedido.detalles.all()) > 0 else "PENDIENTE",
            "total": f"{total:.2f}",
            "total_pagado": f"{total_pagado:.2f}",
            "total_pendiente": f"{total_pendiente:.2f}",
            "productos_confirmados": productos_confirmados,
            "productos_pendientes": productos_pendientes,
            "puede_pagar": puede_pagar,
            "motivo_bloqueo_pago": motivo_bloqueo_pago,
            "metodos_pago": ["STRIPE", "QR", "EFECTIVO"]
        })


class PagarEfectivoView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

    def post(self, request, id):
        from django.db.models import Sum
        from finanzas.models import Pago
        pedido = get_object_or_404(Pedido, id=id)
        if len(pedido.detalles.all()) == 0:
            return Response({'error': 'El pedido está vacío'}, status=status.HTTP_400_BAD_REQUEST)
            
        has_pending = pedido.detalles.filter(confirmado=False).exists()
        if has_pending:
            return Response({'error': 'Confirma los productos pendientes antes de realizar el pago'}, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            pedido = Pedido.objects.select_for_update().get(id=id)
            
            # Recalculate total_pendiente to prevent race conditions
            total_pagado = (
                Pago.objects.filter(pedido=pedido, estado='exitoso')
                .aggregate(Sum('monto'))['monto__sum']
                or Decimal('0.00')
            )
            total_pendiente = total_confirmado_pendiente(pedido, total_pagado)

            if total_pendiente <= Decimal('0.00'):
                return Response({'error': 'El pedido ya está totalmente pagado'}, status=status.HTTP_400_BAD_REQUEST)

            # Create Pago
            pago = Pago.objects.create(
                pedido=pedido,
                monto=total_pendiente,
                metodo_pago='efectivo',
                estado='exitoso',
                usuario=request.user
            )

            # Update pedido state
            pedido.estado = 'confirmado'
            pedido.save()

            # Automatically liberate the table if no other unpaid orders remain
            from pedidos.services import mesa_tiene_deudas_activas
            tiene_deudas = mesa_tiene_deudas_activas(pedido.mesa, exclude_pedido_id=pedido.id)

            estado_mesa = "OCUPADA"
            if not tiene_deudas:
                if pedido.mesa:
                    pedido.mesa.estado = 'disponible'
                    pedido.mesa.save()
                    estado_mesa = "LIBRE"

            Bitacora.objects.create(
                usuario=request.user,
                accion='registrar pago efectivo',
                detalles=f'Pago en efectivo de Bs. {total_pendiente:.2f} registrado para pedido ID {pedido.id}.'
            )

            return Response({
                "message": "Pago en efectivo registrado correctamente",
                "metodo_pago": "EFECTIVO",
                "monto_pagado": f"{total_pendiente:.2f}",
                "total_pendiente": "0.00",
                "estado_pago": "PAGADO",
                "estado_mesa": estado_mesa
            }, status=status.HTTP_200_OK)
