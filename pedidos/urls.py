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
)

router = DefaultRouter()
router.register(r'pedidos', PedidoViewSet, basename='pedidos')
router.register(r'preordenes', PreordenViewSet, basename='preordenes')

urlpatterns = [
    path('cocina/perfil/', CocinaPerfilView.as_view(), name='cocina-perfil'),
    path('cocina/comandas/', CocinaComandasView.as_view(), name='cocina-comandas'),
    path('cocina/comandas/<int:id>/', CocinaComandaDetailView.as_view(), name='cocina-comanda-detail'),
    path('cocina/comandas/<int:id>/en-preparacion/', CocinaComandaEnPreparacionView.as_view(), name='cocina-comanda-en-preparacion'),
    path('cocina/comandas/<int:id>/lista/', CocinaComandaListaView.as_view(), name='cocina-comanda-lista'),
    path('', include(router.urls)),
]
