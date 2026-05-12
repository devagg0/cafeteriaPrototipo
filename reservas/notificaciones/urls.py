from django.urls import path
from . import views

urlpatterns = [

    path('', views.historial_notificaciones),

    path(
        'enviar/',
        views.enviar_notificacion_manual
    ),

    path(
        'mis-notificaciones/<str:cliente_id>/',
        views.mis_notificaciones
    ),

]