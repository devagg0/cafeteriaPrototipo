from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='api-login'),
    path('logout/', views.logout_view, name='api-logout'),

    path('usuarios/', views.lista_usuarios, name='api-user-list'),
    path('usuarios/<int:user_id>/', views.detalle_usuario, name='api-user-detail'),
    path('usuarios/<int:user_id>/rol/', views.asignar_rol, name='api-assign-role'),

    path('roles/', views.lista_roles, name='api-role-list'),

    path('empleados/', views.lista_empleados, name='api-employee-list'),
    path('empleados/<int:employee_id>/', views.detalle_empleado, name='api-employee-detail'),

    path('clientes/', views.lista_clientes, name='api-customer-list'),
    path('clientes/<int:customer_id>/', views.detalle_cliente, name='api-customer-detail'),
]
