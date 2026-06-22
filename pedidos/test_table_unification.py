from django.test import TestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.test import APIRequestFactory, force_authenticate

from usuarios.models import Usuario, Rol, Cliente
from reservas.models import SalaTematica, Mesa, Reserva
from producto.models import Categoria, Producto
from pedidos.models import Pedido, DetallePedido
from finanzas.models import Pago

from pedidos.services import obtener_pedido_activo, mesa_tiene_deudas_activas
from reservas.serializers import MesaSerializer
from pedidos.serializers import PedidoSerializer
from pedidos.views import PedidoActivoMesaView, IniciarPedidoMesaView

class TableUnificationTestCase(TestCase):
    def setUp(self):
        # Get or Create Roles
        self.rol_mesero, _ = Rol.objects.get_or_create(cod_rol='mesero', defaults={'nombre': 'Mesero', 'descripcion': 'Mesero de la cafeteria'})
        self.rol_admin, _ = Rol.objects.get_or_create(cod_rol='admin', defaults={'nombre': 'Admin', 'descripcion': 'Administrador'})

        # Create Users
        self.usuario_mesero = Usuario.objects.create(
            nombre="Mesero Pepe",
            correo="pepe@cafeteria.com",
            contrasena="123456",
            cod_rol=self.rol_mesero
        )
        self.usuario_admin = Usuario.objects.create(
            nombre="Admin Carlos",
            correo="carlos@cafeteria.com",
            contrasena="123456",
            cod_rol=self.rol_admin
        )

        # Create Sala and Mesa
        self.sala = SalaTematica.objects.create(
            nombre="Sala Retro",
            capacidad_total=20,
            disponibilidad="disponible"
        )
        self.mesa = Mesa.objects.create(
            sala=self.sala,
            nombre="Mesa 1",
            capacidad=4,
            estado="disponible"
        )

        # Create Product
        self.categoria = Categoria.objects.create(nombre="Bebidas", estado=True)
        self.producto = Producto.objects.create(
            categoria=self.categoria,
            nombre="Café Expreso",
            precio=12.50,
            stock=100
        )

        self.factory = APIRequestFactory()

    def test_mesa_without_order_is_libre(self):
        # 1. No orders exist for the mesa
        pedido = obtener_pedido_activo(self.mesa)
        self.assertIsNone(pedido)
        self.assertFalse(mesa_tiene_deudas_activas(self.mesa))

        serializer = MesaSerializer(self.mesa)
        # to_representation overrides the state to available/disponible
        repr_data = serializer.to_representation(self.mesa)
        self.assertEqual(repr_data['estado'], 'disponible')
        self.assertEqual(repr_data['cantidad_productos'], 0)
        self.assertEqual(repr_data['total_pendiente'], 0.0)

    def test_mesa_with_empty_order_is_libre(self):
        # 2. An empty active order is created by a mesero
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.usuario_mesero,
            total=0.00,
            estado='pendiente'
        )
        # Should return the empty order as the active one (so they can add products)
        active_pedido = obtener_pedido_activo(self.mesa)
        self.assertEqual(active_pedido, pedido)

        # But since it has no details, it does not count as active debt
        self.assertFalse(mesa_tiene_deudas_activas(self.mesa))

        # Under the new logic, visual status is libre ('disponible')
        serializer = MesaSerializer(self.mesa)
        repr_data = serializer.to_representation(self.mesa)
        self.assertEqual(repr_data['estado'], 'disponible')

        # Check PedidoSerializer output for state
        ped_serializer = PedidoSerializer(pedido)
        self.assertEqual(ped_serializer.data['estado_mesa'], 'LIBRE')

    def test_mesa_with_unconfirmed_details_is_ocupada(self):
        # 3. Order has unconfirmed details
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.usuario_mesero,
            total=12.50,
            estado='pendiente'
        )
        DetallePedido.objects.create(
            pedido=pedido,
            producto=self.producto,
            cantidad=1,
            precio_unitario=self.producto.precio,
            subtotal=self.producto.precio,
            confirmado=False
        )

        active_pedido = obtener_pedido_activo(self.mesa)
        self.assertEqual(active_pedido, pedido)
        self.assertTrue(mesa_tiene_deudas_activas(self.mesa))

        # Visual status should be ocupada
        serializer = MesaSerializer(self.mesa)
        repr_data = serializer.to_representation(self.mesa)
        self.assertEqual(repr_data['estado'], 'ocupada')
        self.assertEqual(repr_data['cantidad_productos'], 1)
        # total_pendiente should only include confirmed products, so Bs 0.00 here
        self.assertEqual(repr_data['total_pendiente'], 0.0)

        # Check PedidoSerializer output for state
        ped_serializer = PedidoSerializer(pedido)
        self.assertEqual(ped_serializer.data['estado_mesa'], 'OCUPADA')
        self.assertEqual(ped_serializer.data['total_pendiente'], 0.0)
        self.assertEqual(ped_serializer.data['cantidad_pendientes'], 1)

    def test_mesa_with_confirmed_unpaid_details_is_ocupada(self):
        # 4. Order has confirmed unpaid details
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.usuario_mesero,
            total=12.50,
            estado='confirmado'
        )
        DetallePedido.objects.create(
            pedido=pedido,
            producto=self.producto,
            cantidad=1,
            precio_unitario=self.producto.precio,
            subtotal=self.producto.precio,
            confirmado=True
        )

        active_pedido = obtener_pedido_activo(self.mesa)
        self.assertEqual(active_pedido, pedido)
        self.assertTrue(mesa_tiene_deudas_activas(self.mesa))

        serializer = MesaSerializer(self.mesa)
        repr_data = serializer.to_representation(self.mesa)
        self.assertEqual(repr_data['estado'], 'ocupada')
        self.assertEqual(repr_data['cantidad_productos'], 1)
        self.assertEqual(repr_data['total_pendiente'], 12.50)

        # Check PedidoSerializer output for state
        ped_serializer = PedidoSerializer(pedido)
        self.assertEqual(ped_serializer.data['estado_mesa'], 'OCUPADA')
        self.assertEqual(ped_serializer.data['total_pendiente'], 12.50)
        self.assertEqual(ped_serializer.data['cantidad_confirmados'], 1)

    def test_mesa_fully_paid_is_libre(self):
        # 5. Order is fully paid
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.usuario_mesero,
            total=12.50,
            estado='confirmado'
        )
        DetallePedido.objects.create(
            pedido=pedido,
            producto=self.producto,
            cantidad=1,
            precio_unitario=self.producto.precio,
            subtotal=self.producto.precio,
            confirmado=True
        )

        # Create successful payment
        Pago.objects.create(
            pedido=pedido,
            monto=12.50,
            metodo_pago='stripe',
            estado='exitoso',
            usuario=self.usuario_mesero
        )

        # Since it has no unconfirmed details and total_pendiente is 0,
        # it is no longer an active order!
        active_pedido = obtener_pedido_activo(self.mesa)
        self.assertIsNone(active_pedido)
        self.assertFalse(mesa_tiene_deudas_activas(self.mesa))

        serializer = MesaSerializer(self.mesa)
        repr_data = serializer.to_representation(self.mesa)
        self.assertEqual(repr_data['estado'], 'disponible')
        self.assertEqual(repr_data['cantidad_productos'], 0)
        self.assertEqual(repr_data['total_pendiente'], 0.0)

    def test_no_duplicate_orders_for_same_mesa(self):
        # Create an active order
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.usuario_mesero,
            total=12.50,
            estado='pendiente'
        )
        DetallePedido.objects.create(
            pedido=pedido,
            producto=self.producto,
            cantidad=1,
            precio_unitario=self.producto.precio,
            subtotal=self.producto.precio,
            confirmado=False
        )

        # Try to initiate another order via view
        view = IniciarPedidoMesaView.as_view()
        request = self.factory.post(f'/api/pedidos/mesa/{self.mesa.id}/iniciar/')
        force_authenticate(request, user=self.usuario_mesero)
        response = view(request, mesa_id=self.mesa.id)

        # Under unified logic, it should return the EXISTING order instead of creating a new one
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['id'], pedido.id)
        
        # Verify only 1 pedido exists
        self.assertEqual(Pedido.objects.filter(mesa=self.mesa).count(), 1)

    def test_viewing_active_order_does_not_create_empty_order(self):
        # 7. Viewing active order on an empty table returns 404 and does not create an order
        view = PedidoActivoMesaView.as_view()
        request = self.factory.get(f'/api/pedidos/mesa/{self.mesa.id}/activo/')
        force_authenticate(request, user=self.usuario_mesero)
        response = view(request, mesa_id=self.mesa.id)

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(Pedido.objects.filter(mesa=self.mesa).count(), 0)
