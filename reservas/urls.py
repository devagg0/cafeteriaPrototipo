from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SalaTematicaViewSet, MesaViewSet, ReservaViewSet, MesaEstadoView

router = DefaultRouter()
router.register(r'salas', SalaTematicaViewSet, basename='salas')
router.register(r'mesas', MesaViewSet, basename='mesas')
router.register(r'reservas', ReservaViewSet, basename='reservas')

urlpatterns = [
    path('mesas/<int:pk>/estado/', MesaEstadoView.as_view(), name='mesa-estado'),
    path('', include(router.urls)),

    #  CU13
    path('asistencia/', include('reservas.asistencia.urls')),

    #  CU14
    path('notificaciones/', include('reservas.notificaciones.urls')),
]