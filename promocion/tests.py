from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from pedidos.models import DetallePedido, Pedido
from producto.models import Categoria, Producto
from reservas.models import Mesa, SalaTematica
from usuarios.models import Rol, Usuario

from .models import Promocion


class PromocionesTests(TestCase):
    def setUp(self):
        rol_admin, _ = Rol.objects.get_or_create(
            cod_rol='admin',
            defaults={'nombre': 'Admin'},
        )
        rol_mesero, _ = Rol.objects.get_or_create(
            cod_rol='mesero',
            defaults={'nombre': 'Mesero'},
        )
        self.admin = Usuario.objects.create(
            nombre='Admin promociones',
            correo='admin-promociones@example.com',
            contrasena='test',
            cod_rol=rol_admin,
        )
        self.mesero = Usuario.objects.create(
            nombre='Mesero promociones',
            correo='mesero-promociones@example.com',
            contrasena='test',
            cod_rol=rol_mesero,
        )
        self.categoria = Categoria.objects.create(nombre='Promociones')
        self.producto = Producto.objects.create(
            categoria=self.categoria,
            nombre='Producto promocional',
            precio=Decimal('100.00'),
            stock=10,
            estado=True,
        )
        self.sala = SalaTematica.objects.create(nombre='Sala promociones')
        self.mesa = Mesa.objects.create(
            sala=self.sala,
            nombre='Mesa promociones',
            capacidad=4,
            estado='ocupada',
        )
        self.pedido = Pedido.objects.create(
            sala=self.sala,
            mesa=self.mesa,
            usuario=self.mesero,
            estado='confirmado',
            total=Decimal('100.00'),
        )
        DetallePedido.objects.create(
            pedido=self.pedido,
            producto=self.producto,
            cantidad=1,
            precio_unitario=Decimal('100.00'),
            subtotal=Decimal('100.00'),
            confirmado=True,
        )
        hoy = timezone.localdate()
        self.promocion = Promocion.objects.create(
            codigo='promo10',
            nombre='Diez por ciento',
            tipo_descuento='porcentaje',
            valor_descuento=Decimal('10.00'),
            fecha_inicio=hoy - timedelta(days=1),
            fecha_fin=hoy + timedelta(days=1),
            activa=True,
        )

    def test_admin_gestiona_promociones_y_codigo_se_normaliza(self):
        api = APIClient()
        api.force_authenticate(user=self.admin)
        respuesta = api.post(
            reverse('promociones-list'),
            {
                'codigo': ' verano20 ',
                'nombre': 'Verano',
                'tipo_descuento': 'monto_fijo',
                'valor_descuento': '20.00',
                'fecha_inicio': timezone.localdate(),
                'fecha_fin': timezone.localdate() + timedelta(days=2),
                'activa': True,
                'productos': [self.producto.id],
                'categorias': [],
            },
            format='json',
        )

        self.assertEqual(respuesta.status_code, 201)
        self.assertEqual(respuesta.data['codigo'], 'VERANO20')
        self.assertEqual(respuesta.data['nombres_productos'], [self.producto.nombre])

    def test_promocion_actualiza_total_resumen_y_pago(self):
        api = APIClient()
        api.force_authenticate(user=self.mesero)

        aplicada = api.post(
            reverse('pedidos-aplicar-promocion', args=[self.pedido.id]),
            {'codigo': 'PROMO10'},
            format='json',
        )
        self.assertEqual(aplicada.status_code, 200)
        self.assertEqual(aplicada.data['descuento'], '10.00')
        self.assertEqual(aplicada.data['total'], 90.0)

        resumen = api.get(reverse('resumen-pago-pedido', args=[self.pedido.id]))
        self.assertEqual(resumen.status_code, 200)
        self.assertEqual(resumen.data['total_pendiente'], '90.00')

        pago_qr = api.post(
            reverse('iniciar-pago-pedido'),
            {
                'pedido_id': self.pedido.id,
                'metodo_pago': 'qr',
            },
            format='json',
        )
        self.assertEqual(pago_qr.status_code, 201)
        self.assertEqual(pago_qr.data['total'], 90.0)

        pago = api.post(reverse('pagar-efectivo-pedido', args=[self.pedido.id]))
        self.assertEqual(pago.status_code, 200)
        self.assertEqual(pago.data['monto_pagado'], '90.00')
        self.mesa.refresh_from_db()
        self.assertEqual(self.mesa.estado, 'disponible')

    def test_promocion_no_aplicable_no_se_conserva(self):
        otra_categoria = Categoria.objects.create(nombre='Otra categoría')
        otro_producto = Producto.objects.create(
            categoria=otra_categoria,
            nombre='Producto ajeno',
            precio=Decimal('20.00'),
            stock=5,
            estado=True,
        )
        self.promocion.productos.add(otro_producto)
        api = APIClient()
        api.force_authenticate(user=self.mesero)

        respuesta = api.post(
            reverse('pedidos-aplicar-promocion', args=[self.pedido.id]),
            {'codigo': self.promocion.codigo},
            format='json',
        )

        self.assertEqual(respuesta.status_code, 400)
        self.pedido.refresh_from_db()
        self.assertIsNone(self.pedido.promocion)
        self.assertEqual(self.pedido.descuento, Decimal('0.00'))
