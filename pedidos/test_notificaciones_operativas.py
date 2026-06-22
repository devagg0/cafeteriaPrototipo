from datetime import time

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from producto.models import Categoria, Producto
from reservas.models import Mesa, Reserva, SalaTematica
from usuarios.models import Cliente, Rol, Usuario

from .models import DetallePedido, DetallePreorden, Notificacion, Pedido, Preorden
from .services import (
    convertir_preorden_a_pedido_por_checkin,
    notificar_pedido_a_cocina,
    notificar_pedido_listo_al_mesero,
)


class NotificacionesOperativasTests(TestCase):
    def setUp(self):
        self.rol_cliente, _ = Rol.objects.get_or_create(cod_rol='cliente', defaults={'nombre': 'Cliente'})
        self.rol_mesero, _ = Rol.objects.get_or_create(cod_rol='mesero', defaults={'nombre': 'Mesero'})
        self.rol_cocinero, _ = Rol.objects.get_or_create(cod_rol='cocinero', defaults={'nombre': 'Cocinero'})
        self.cliente_usuario = Usuario.objects.create(
            nombre='Daniel',
            correo='daniel-notificaciones@example.com',
            contrasena='test',
            cod_rol=self.rol_cliente,
        )
        self.cliente = Cliente.objects.create(
            cod_cliente='NOT001',
            direccion='Prueba',
            id_usuario=self.cliente_usuario,
        )
        self.mesero = Usuario.objects.create(
            nombre='Mesero prueba',
            correo='mesero-notificaciones@example.com',
            contrasena='test',
            cod_rol=self.rol_mesero,
        )
        self.cocinero = Usuario.objects.create(
            nombre='Cocinero prueba',
            correo='cocinero-notificaciones@example.com',
            contrasena='test',
            cod_rol=self.rol_cocinero,
        )
        self.sala = SalaTematica.objects.create(nombre='Sala notificaciones')
        self.mesa = Mesa.objects.create(sala=self.sala, nombre='Mesa N1', capacidad=4)
        categoria = Categoria.objects.create(nombre='Categoría notificaciones', estado=True)
        self.producto = Producto.objects.create(
            categoria=categoria,
            nombre='Café notificaciones',
            precio=12,
            stock=20,
            estado=True,
        )

    def test_checkin_de_preorden_notifica_una_sola_vez_a_cocina(self):
        reserva = Reserva.objects.create(
            cliente=self.cliente,
            sala=self.sala,
            mesa=self.mesa,
            fecha=timezone.localdate(),
            hora_inicio=time(10, 0),
            hora_fin=time(11, 0),
            cantidad_personas=2,
            estado='en_curso',
        )
        preorden = Preorden.objects.create(
            reserva=reserva,
            cliente=self.cliente,
            sala=self.sala,
            mesa=self.mesa,
            usuario_mesero=self.mesero,
            estado='apartada',
            total=12,
        )
        DetallePreorden.objects.create(
            preorden=preorden,
            producto=self.producto,
            cantidad=1,
            precio_unitario=12,
            subtotal=12,
        )

        resultado = convertir_preorden_a_pedido_por_checkin(reserva, self.mesero)
        pedido = Pedido.objects.get(id=resultado['pedido_id'])
        notificar_pedido_a_cocina(pedido)

        notificaciones = Notificacion.objects.filter(
            usuario_destino=self.cocinero,
            pedido=pedido,
            tipo='nuevo_pedido',
        )
        self.assertEqual(notificaciones.count(), 1)
        self.assertIn('Daniel', notificaciones.get().mensaje)

    def test_pedido_listo_notifica_una_sola_vez_al_mesero(self):
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.mesero,
            cliente=self.cliente,
            nombre_cliente='Daniel',
            estado='lista',
            total=12,
        )

        self.assertTrue(notificar_pedido_listo_al_mesero(pedido))
        self.assertFalse(notificar_pedido_listo_al_mesero(pedido))
        self.assertEqual(
            Notificacion.objects.filter(
                usuario_destino=self.mesero,
                pedido=pedido,
                tipo='pedido_listo',
            ).count(),
            1,
        )

    def test_mesero_inicia_pedido_con_cliente_registrado(self):
        api = APIClient()
        api.force_authenticate(user=self.mesero)

        respuesta = api.post(
            reverse('iniciar-pedido-mesa', args=[self.mesa.id]),
            {'cliente_id': self.cliente_usuario.id_usuario},
            format='json',
        )

        self.assertEqual(respuesta.status_code, 201)
        pedido = Pedido.objects.get(id=respuesta.data['id'])
        self.assertEqual(pedido.cliente, self.cliente)
        self.assertEqual(pedido.nombre_cliente, 'Daniel')

    def test_usuario_solo_ve_y_marca_sus_notificaciones(self):
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.mesero,
            nombre_cliente='Cliente presencial',
            estado='confirmado',
        )
        notificar_pedido_a_cocina(pedido)
        api = APIClient()
        api.force_authenticate(user=self.cocinero)

        listado = api.get(reverse('notificaciones-operativas'))
        self.assertEqual(listado.status_code, 200)
        self.assertEqual(listado.data['no_leidas'], 1)
        notificacion_id = listado.data['results'][0]['id']

        leida = api.patch(reverse('notificacion-operativa-leer', args=[notificacion_id]))
        self.assertEqual(leida.status_code, 200)
        self.assertTrue(leida.data['leido'])
