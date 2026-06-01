from django.urls import path
from .views import HistorialListView, HistorialDetailView
from .views import ClientesSugerenciasView

urlpatterns = [
    path('', HistorialListView.as_view(), name='historial-list'),
    path('<int:id>/', HistorialDetailView.as_view(), name='historial-detail'),
    path('clientes-sugerencias/', ClientesSugerenciasView.as_view(), name='clientes-sugerencias'),
]
