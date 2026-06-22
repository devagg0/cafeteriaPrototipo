from datetime import datetime, time, timedelta
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from pedidos.models import DetallePedido, Pedido
from producto.models import Categoria, Producto
from usuarios.models import Cliente, Rol, Usuario

from .models import Mesa, NotificacionReserva, Reserva, SalaTematica
from .notificaciones.services import marcar_notificacion_leida
from .services import (
    sincronizar_reservas_vencidas,
    validar_cancelacion_cliente,
    validar_horario_checkin,
)


class FlujoHorarioReservaTests(TestCase):
    def setUp(self):
        rol_cliente, _ = Rol.objects.get_or_create(
            cod_rol='cliente',
            defaults={'nombre': 'Cliente'},
        )
        rol_admin, _ = Rol.objects.get_or_create(
            cod_rol='admin',
            defaults={'nombre': 'Admin'},
        )
        self.usuario = Usuario.objects.create(
            nombre='Cliente prueba',
            correo='cliente-reservas@example.com',
            contrasena='test',
            cod_rol=rol_cliente,
        )
        self.cliente = Cliente.objects.create(
            cod_cliente='CLT001',
            telefono='70000000',
            direccion='Prueba',
            id_usuario=self.usuario,
        )
        self.admin = Usuario.objects.create(
            nombre='Admin prueba',
            correo='admin-reservas@example.com',
            contrasena='test',
            cod_rol=rol_admin,
        )
        self.sala = SalaTematica.objects.create(nombre='Sala prueba', habilitada=True)
        self.mesa = Mesa.objects.create(
            sala=self.sala,
            nombre='Mesa 1',
            capacidad=4,
            estado='reservada',
        )

    def crear_reserva(self, inicio, fin, estado='confirmada'):
        return Reserva.objects.create(
            cliente=self.cliente,
            sala=self.sala,
            mesa=self.mesa,
            fecha=inicio.date(),
            hora_inicio=inicio.time(),
            hora_fin=fin.time(),
            cantidad_personas=2,
            estado=estado,
        )

    def hora_local_estable(self):
        return timezone.make_aware(
            datetime.combine(timezone.localdate(), time(12, 0)),
            timezone.get_current_timezone(),
        )

    def test_cliente_solo_cancela_con_30_minutos_de_anticipacion(self):
        ahora = timezone.localtime().replace(microsecond=0)
        permitida = self.crear_reserva(
            ahora + timedelta(minutes=31),
            ahora + timedelta(hours=1),
        )
        bloqueada = self.crear_reserva(
            ahora + timedelta(minutes=29),
            ahora + timedelta(hours=1),
        )

        self.assertTrue(validar_cancelacion_cliente(permitida, ahora)[0])
        puede_cancelar, mensaje = validar_cancelacion_cliente(bloqueada, ahora)
        self.assertFalse(puede_cancelar)
        self.assertIn('30 minutos de anticipación', mensaje)
        self.assertNotIn('soporte', mensaje.lower())

    def test_checkin_se_habilita_desde_30_minutos_antes(self):
        ahora = self.hora_local_estable()
        demasiado_temprano = self.crear_reserva(
            ahora + timedelta(minutes=31),
            ahora + timedelta(hours=1),
        )
        dentro_de_ventana = self.crear_reserva(
            ahora + timedelta(minutes=30),
            ahora + timedelta(hours=1),
        )

        self.assertFalse(validar_horario_checkin(demasiado_temprano, ahora)[0])
        self.assertTrue(validar_horario_checkin(dentro_de_ventana, ahora)[0])

    def test_reserva_en_curso_vencida_finaliza_y_libera_mesa(self):
        ahora = timezone.localtime().replace(microsecond=0)
        reserva = self.crear_reserva(
            ahora - timedelta(hours=1),
            ahora - timedelta(minutes=1),
            estado='en_curso',
        )
        self.mesa.estado = 'ocupada'
        self.mesa.save(update_fields=['estado'])

        sincronizar_reservas_vencidas(ahora)

        reserva.refresh_from_db()
        self.mesa.refresh_from_db()
        self.assertEqual(reserva.estado, 'finalizada')
        self.assertEqual(self.mesa.estado, 'disponible')

    def test_cancelacion_del_cliente_libera_la_mesa(self):
        ahora = timezone.localtime().replace(microsecond=0)
        reserva = self.crear_reserva(
            ahora + timedelta(hours=2),
            ahora + timedelta(hours=3),
        )
        api = APIClient()
        api.force_authenticate(user=self.usuario)

        respuesta = api.patch(reverse('reservas-cancelar', args=[reserva.id]))

        self.assertEqual(respuesta.status_code, 200)
        reserva.refresh_from_db()
        self.mesa.refresh_from_db()
        self.assertEqual(reserva.estado, 'cancelada')
        self.assertEqual(self.mesa.estado, 'disponible')

    def test_reserva_confirmada_futura_no_bloquea_la_mesa_actualmente(self):
        ahora = timezone.localtime().replace(microsecond=0)
        reserva = self.crear_reserva(
            ahora + timedelta(hours=2),
            ahora + timedelta(hours=3),
            estado='pendiente',
        )
        api = APIClient()
        api.force_authenticate(user=self.admin)

        respuesta = api.patch(reverse('reservas-confirmar', args=[reserva.id]))

        self.assertEqual(respuesta.status_code, 200)
        self.mesa.refresh_from_db()
        self.assertEqual(self.mesa.estado, 'disponible')

    def test_reserva_confirmada_en_ventana_bloquea_la_mesa(self):
        ahora = self.hora_local_estable()
        reserva = self.crear_reserva(
            ahora + timedelta(minutes=20),
            ahora + timedelta(hours=1),
            estado='pendiente',
        )
        api = APIClient()
        api.force_authenticate(user=self.admin)

        with patch('reservas.services.timezone.now', return_value=ahora):
            respuesta = api.patch(reverse('reservas-confirmar', args=[reserva.id]))

        self.assertEqual(respuesta.status_code, 200)
        self.mesa.refresh_from_db()
        self.assertEqual(self.mesa.estado, 'reservada')

    def test_cancelar_no_deja_mesa_bloqueada_por_otra_reserva_futura(self):
        ahora = timezone.localtime().replace(microsecond=0)
        reserva_cancelada = self.crear_reserva(
            ahora + timedelta(hours=2),
            ahora + timedelta(hours=3),
        )
        self.crear_reserva(
            ahora + timedelta(hours=4),
            ahora + timedelta(hours=5),
        )
        api = APIClient()
        api.force_authenticate(user=self.usuario)

        respuesta = api.patch(reverse('reservas-cancelar', args=[reserva_cancelada.id]))

        self.assertEqual(respuesta.status_code, 200)
        self.mesa.refresh_from_db()
        self.assertEqual(self.mesa.estado, 'disponible')

    def test_cancelar_reserva_no_libera_una_mesa_con_pedido_activo(self):
        ahora = timezone.localtime().replace(microsecond=0)
        reserva = self.crear_reserva(
            ahora + timedelta(hours=2),
            ahora + timedelta(hours=3),
        )
        categoria = Categoria.objects.create(nombre='Categoría ocupación', estado=True)
        producto = Producto.objects.create(
            categoria=categoria,
            nombre='Producto ocupación',
            precio=10,
            stock=10,
            estado=True,
        )
        pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.admin,
            total=10,
            estado='pendiente',
        )
        DetallePedido.objects.create(
            pedido=pedido,
            producto=producto,
            cantidad=1,
            precio_unitario=10,
            subtotal=10,
            confirmado=False,
        )
        self.mesa.estado = 'ocupada'
        self.mesa.save(update_fields=['estado'])
        api = APIClient()
        api.force_authenticate(user=self.usuario)

        respuesta = api.patch(reverse('reservas-cancelar', args=[reserva.id]))

        self.assertEqual(respuesta.status_code, 200)
        self.mesa.refresh_from_db()
        self.assertEqual(self.mesa.estado, 'ocupada')

    def test_cliente_puede_marcar_su_notificacion_como_leida(self):
        ahora = timezone.localtime().replace(microsecond=0)
        reserva = self.crear_reserva(
            ahora + timedelta(hours=2),
            ahora + timedelta(hours=3),
        )
        notificacion = NotificacionReserva.objects.create(
            reserva=reserva,
            tipo='confirmacion',
            mensaje='Reserva confirmada',
        )

        resultado = marcar_notificacion_leida(notificacion, self.usuario)

        self.assertTrue(resultado)
        notificacion.refresh_from_db()
        self.assertTrue(notificacion.leido)
