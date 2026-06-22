from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PedidoViewSet,
    PreordenViewSet,
    CocinaPerfilView,
    CocinaComandasView,
    CocinaComandaDetailView,
    CocinaComandaEnPreparacionView,
    CocinaComandaListaView,
    PedidoActivoMesaView,
    IniciarPedidoMesaView,
    AgregarDetallePedidoView,
    ActualizarEliminarDetallePedidoView,
    ConfirmarPedidoView,
    ResumenPagoView,
    PagarEfectivoView,
    ClientesPedidoBuscarView,
    NotificacionesOperativasView,
    NotificacionOperativaLeidaView,
)

router = DefaultRouter()
router.register(r'pedidos', PedidoViewSet, basename='pedidos')
router.register(r'preordenes', PreordenViewSet, basename='preordenes')

urlpatterns = [
    path('pedidos/historial/', include('pedidos.historial.urls')),
    path('cocina/perfil/', CocinaPerfilView.as_view(), name='cocina-perfil'),
    path('cocina/comandas/', CocinaComandasView.as_view(), name='cocina-comandas'),
    path('cocina/comandas/<int:id>/', CocinaComandaDetailView.as_view(), name='cocina-comanda-detail'),
    path('cocina/comandas/<int:id>/en-preparacion/', CocinaComandaEnPreparacionView.as_view(), name='cocina-comanda-en-preparacion'),
    path('cocina/comandas/<int:id>/lista/', CocinaComandaListaView.as_view(), name='cocina-comanda-lista'),
    
    path('pedidos/mesa/<int:mesa_id>/activo/', PedidoActivoMesaView.as_view(), name='pedido-activo-mesa'),
    path('pedidos/mesa/<int:mesa_id>/iniciar/', IniciarPedidoMesaView.as_view(), name='iniciar-pedido-mesa'),
    path('pedidos/<int:pedido_id>/detalles/', AgregarDetallePedidoView.as_view(), name='agregar-detalle-pedido'),
    path('pedidos/<int:pedido_id>/detalles/<int:detalle_id>/', ActualizarEliminarDetallePedidoView.as_view(), name='actualizar-eliminar-detalle-pedido'),
    
    path('pedidos/<int:id>/confirmar/', ConfirmarPedidoView.as_view(), name='confirmar-pedido-detalle'),
    path('pedidos/<int:id>/resumen-pago/', ResumenPagoView.as_view(), name='resumen-pago-pedido'),
    path('pedidos/<int:id>/pagar-efectivo/', PagarEfectivoView.as_view(), name='pagar-efectivo-pedido'),
    path('pedidos/clientes/buscar/', ClientesPedidoBuscarView.as_view(), name='buscar-clientes-pedido'),
    path('pedidos/notificaciones/', NotificacionesOperativasView.as_view(), name='notificaciones-operativas'),
    path('pedidos/notificaciones/<int:pk>/leer/', NotificacionOperativaLeidaView.as_view(), name='notificacion-operativa-leer'),
    
    path('', include(router.urls)),
]
