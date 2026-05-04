from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SalaTematicaViewSet, MesaViewSet, ReservaViewSet

router = DefaultRouter()
router.register(r'salas', SalaTematicaViewSet, basename='salas')
router.register(r'mesas', MesaViewSet, basename='mesas')
router.register(r'reservas', ReservaViewSet, basename='reservas')

urlpatterns = [
    path('', include(router.urls)),
]
