from django.urls import path
from . import views

urlpatterns = [
    path('pendientes/', views.reservas_pendientes),
    path('checkin/<int:reserva_id>/', views.checkin_reserva),
    path('no-asistio/<int:reserva_id>/', views.marcar_no_asistio),
]