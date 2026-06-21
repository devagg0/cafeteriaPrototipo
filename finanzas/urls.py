from django.urls import path
from .views import (
    CrearSesionReservaView,
    IniciarPagoPedidoView,
    ConfirmarPagoStripeView,
    ConfirmarPagoQRView,
    NotaVentaPedidoView,
    CancelarPagoPedidoView,
    CancelarPagoReservaView
)

urlpatterns = [
    path('finanzas/crear-sesion-reserva/', CrearSesionReservaView.as_view(), name='crear-sesion-reserva'),
    path('finanzas/iniciar-pago-pedido/', IniciarPagoPedidoView.as_view(), name='iniciar-pago-pedido'),
    path('finanzas/confirmar-pago-stripe/', ConfirmarPagoStripeView.as_view(), name='confirmar-pago-stripe'),
    path('finanzas/confirmar-pago-qr/', ConfirmarPagoQRView.as_view(), name='confirmar-pago-qr'),
    path('finanzas/nota-venta-pedido/', NotaVentaPedidoView.as_view(), name='nota-venta-pedido'),
    path('finanzas/cancelar-pago-pedido/', CancelarPagoPedidoView.as_view(), name='cancelar-pago-pedido'),
    path('finanzas/cancelar-pago-reserva/', CancelarPagoReservaView.as_view(), name='cancelar-pago-reserva'),
]
