from django.test import TestCase

from finanzas.reportes import reporte_dinamico


class ReportesTests(TestCase):
    def test_reporte_dinamico_mapea_tipo_y_agrupar_por_desde_frontend(self):
        data = reporte_dinamico({
            'tipo': 'Ventas e ingresos',
            'agrupar_por': 'Metodo de pago',
            'fecha_inicio': '2026-06-01',
            'fecha_fin': '2026-06-21',
        })

        self.assertEqual(data['tipo'], 'ingresos')
        self.assertEqual(data['filtros']['agrupar_por'], 'metodo')
