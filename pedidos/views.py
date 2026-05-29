from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import BasePermission
from django.db import transaction
from django.utils import timezone

from producto.models import Categoria, Producto
from producto.serializers import CategoriaSerializer, ProductoSerializer
from .models import Pedido, DetallePedido, Preorden, DetallePreorden
from .serializers import (
    PedidoSerializer, DetallePedidoSerializer,
    PreordenSerializer, DetallePreordenSerializer,
)
from usuarios.models import Usuario, Cliente, Bitacora
from usuarios.views import decodificar_token
from reservas.models import SalaTematica, Mesa, Reserva


# ---------------------------------------------------------------------------
# Auth compartida (duplicada de reservas.views para evitar import circular)
# ---------------------------------------------------------------------------

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None
        token = auth_header.split(' ')[1]
        payload = decodificar_token(token)
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


class IsAuthenticatedJWT(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user)



# ---------------------------------------------------------------------------
# PedidoViewSet
# ---------------------------------------------------------------------------

class PedidoViewSet(viewsets.ModelViewSet):
    queryset = Pedido.objects.select_related('reserva', 'sala', 'mesa', 'usuario').prefetch_related('detalles__producto')
    serializer_class = PedidoSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsEmpleadoOrAdmin]

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

        try:
            sala = SalaTematica.objects.get(id=sala_id)
            mesa = Mesa.objects.get(id=mesa_id, sala=sala)
        except (SalaTematica.DoesNotExist, Mesa.DoesNotExist):
            return Response(
                {'error': 'Sala o Mesa no válidas'},
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

        except ValueError as exc:
            return Response({'error': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(pedido)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


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
