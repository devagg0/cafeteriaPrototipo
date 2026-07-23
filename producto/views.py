from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import BasePermission
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from .models import Categoria, Combo, Producto
from .serializers import CategoriaSerializer, ComboSerializer, ProductoSerializer
from usuarios.models import Usuario
from usuarios.views import decodificar_token


# ---------------------------------------------------------------------------
# Auth compartida (duplicada para evitar import circular)
# ---------------------------------------------------------------------------

class JWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        payload = decodificar_token(token)

        if isinstance(payload, dict) and payload.get('error'):
            raise AuthenticationFailed(payload['error'])

        try:
            user = Usuario.objects.get(id_usuario=payload.get('user_id'))
            return (user, token)
        except Usuario.DoesNotExist:
            raise AuthenticationFailed('Usuario no encontrado')


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return bool(
            request.user and
            request.user.cod_rol.cod_rol == 'admin'
        )


class IsAuthenticatedJWT(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user)


# ---------------------------------------------------------------------------
# CategoriaViewSet
# ---------------------------------------------------------------------------

class CategoriaViewSet(viewsets.ModelViewSet):
    queryset = Categoria.objects.all()
    serializer_class = CategoriaSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticatedJWT()]
        return [IsAdmin()]

    def destroy(self, request, *args, **kwargs):
        categoria = self.get_object()

        if categoria.productos.filter(estado=True).exists():
            return Response(
                {
                    'error': 'No se puede eliminar una categoría con productos activos'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        return super().destroy(request, *args, **kwargs)


# ---------------------------------------------------------------------------
# ProductoViewSet
# ---------------------------------------------------------------------------

class ProductoViewSet(viewsets.ModelViewSet):
    queryset = Producto.objects.all()
    serializer_class = ProductoSerializer
    authentication_classes = [JWTAuthentication]
    parser_classes = [MultiPartParser, FormParser]

    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'disponibles', 'activos']:
            return [IsAuthenticatedJWT()]
        return [IsAdmin()]

    @action(detail=False, methods=['get'])
    def disponibles(self, request):
        """
        Productos activos con stock mayor a 0.
        """
        qs = Producto.objects.filter(
            estado=True,
            stock__gt=0,
            categoria__estado=True
        )

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=False, methods=['get'])
    def activos(self, request):
        """
        Productos activos (aunque no tengan stock).
        Ruta:
            GET /api/productos/activos/
        """
        qs = Producto.objects.filter(
            estado=True,
            categoria__estado=True
        )

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)


# ---------------------------------------------------------------------------
# ComboViewSet
# ---------------------------------------------------------------------------

class ComboViewSet(viewsets.ModelViewSet):
    queryset = Combo.objects.prefetch_related(
        'detalles__producto'
    ).all()

    serializer_class = ComboSerializer
    authentication_classes = [JWTAuthentication]

    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'activos']:
            return [IsAuthenticatedJWT()]
        return [IsAdmin()]

    @action(detail=False, methods=['get'])
    def activos(self, request):
        """
        Combos activos.
        """
        qs = self.get_queryset().filter(
            estado=True
        )

        serializer = self.get_serializer(qs, many=True)
        return Response(serializer.data)