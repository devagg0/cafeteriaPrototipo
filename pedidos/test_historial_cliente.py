from datetime import time

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from producto.models import Categoria, Producto
from reservas.models import Mesa, Reserva, SalaTematica
from usuarios.models import Cliente, Rol, Usuario

from .models import DetallePedido, Pedido


class HistorialPedidosClienteTests(TestCase):
    def setUp(self):
        rol_cliente, _ = Rol.objects.get_or_create(
            cod_rol='cliente',
            defaults={'nombre': 'Cliente'},
        )
        self.usuario = Usuario.objects.create(
            nombre='Cliente historial',
            correo='cliente-historial@example.com',
            contrasena='test',
            cod_rol=rol_cliente,
        )
        self.cliente = Cliente.objects.create(
            cod_cliente='HIS001',
            telefono='70000000',
            direccion='Prueba',
            id_usuario=self.usuario,
        )
        self.sala = SalaTematica.objects.create(nombre='Sala historial')
        self.mesa = Mesa.objects.create(sala=self.sala, nombre='Mesa historial', capacidad=4)
        categoria = Categoria.objects.create(nombre='Categoría historial', estado=True)
        self.producto = Producto.objects.create(
            categoria=categoria,
            nombre='Producto historial',
            precio=10,
            stock=20,
            estado=True,
        )
        self.api = APIClient()
        self.api.force_authenticate(user=self.usuario)

    def crear_pedido(self, reserva=None):
        pedido = Pedido.objects.create(
            reserva=reserva,
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.usuario,
            total=10,
            estado='entregada',
        )
        DetallePedido.objects.create(
            pedido=pedido,
            producto=self.producto,
            cantidad=1,
            precio_unitario=10,
            subtotal=10,
        )
        return pedido

    def test_cliente_consulta_pedidos_directos_y_de_reserva(self):
        reserva = Reserva.objects.create(
            cliente=self.cliente,
            sala=self.sala,
            mesa=self.mesa,
            fecha=timezone.localdate(),
            hora_inicio=time(10, 0),
            hora_fin=time(11, 0),
            cantidad_personas=2,
            estado='finalizada',
        )
        pedido_reserva = self.crear_pedido(reserva)
        pedido_directo = self.crear_pedido()

        respuesta = self.api.get(reverse('historial-list'))

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.data['count'], 2)
        self.assertEqual(
            {pedido['id'] for pedido in respuesta.data['results']},
            {pedido_reserva.id, pedido_directo.id},
        )

    def test_cliente_consulta_detalle_de_su_pedido(self):
        pedido = self.crear_pedido()

        respuesta = self.api.get(reverse('historial-detail', args=[pedido.id]))

        self.assertEqual(respuesta.status_code, 200)
        self.assertEqual(respuesta.data['id'], pedido.id)
        self.assertEqual(len(respuesta.data['detalle']), 1)

    def test_cliente_ve_pedido_presencial_asociado_a_su_cuenta(self):
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=Usuario.objects.get(correo='admin@cafeteria.com'),
            cliente=self.cliente,
            nombre_cliente=self.usuario.nombre,
            total=10,
            estado='entregada',
        )
        DetallePedido.objects.create(
            pedido=pedido,
            producto=self.producto,
            cantidad=1,
            precio_unitario=10,
            subtotal=10,
        )

        listado = self.api.get(reverse('historial-list'))
        detalle = self.api.get(reverse('historial-detail', args=[pedido.id]))

        self.assertEqual(listado.status_code, 200)
        self.assertEqual(listado.data['count'], 1)
        self.assertEqual(listado.data['results'][0]['cliente'], self.usuario.nombre)
        self.assertEqual(detalle.status_code, 200)
