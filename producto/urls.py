from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CategoriaViewSet, ComboViewSet, ProductoViewSet

router = DefaultRouter()
router.register(r'categorias', CategoriaViewSet, basename='categorias')
router.register(r'productos', ProductoViewSet, basename='productos')
router.register(r'combos', ComboViewSet, basename='combos')

urlpatterns = [
    path('', include(router.urls)),
]
