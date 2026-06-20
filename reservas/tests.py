from datetime import timedelta

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from usuarios.models import Cliente, Rol, Usuario

from .models import Mesa, Reserva, SalaTematica
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
        ahora = timezone.localtime().replace(microsecond=0)
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
