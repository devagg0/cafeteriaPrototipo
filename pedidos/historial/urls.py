from django.urls import path
from .views import HistorialListView, HistorialDetailView, PedidosActualesView, PedidoEditarView
from .views import ClientesSugerenciasView

urlpatterns = [
    path('', HistorialListView.as_view(), name='historial-list'),
    path('actuales/', PedidosActualesView.as_view(), name='pedidos-actuales'),
    path('<int:id>/editar/', PedidoEditarView.as_view(), name='pedido-editar'),
    path('<int:id>/', HistorialDetailView.as_view(), name='historial-detail'),
    path('clientes-sugerencias/', ClientesSugerenciasView.as_view(), name='clientes-sugerencias'),
]
