from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SalaTematicaViewSet, MesaViewSet, ReservaViewSet,
    CategoriaViewSet, ProductoViewSet, PedidoViewSet
)

router = DefaultRouter()
router.register(r'salas', SalaTematicaViewSet, basename='salas')
router.register(r'mesas', MesaViewSet, basename='mesas')
router.register(r'reservas', ReservaViewSet, basename='reservas')
router.register(r'categorias', CategoriaViewSet, basename='categorias')
router.register(r'productos', ProductoViewSet, basename='productos')
router.register(r'pedidos', PedidoViewSet, basename='pedidos')

urlpatterns = [
    path('', include(router.urls)),

    #  CU13
    path('asistencia/', include('reservas.asistencia.urls')),

    #  CU14
    path('notificaciones/', include('reservas.notificaciones.urls')),
]