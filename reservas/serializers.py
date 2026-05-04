from rest_framework import serializers
from .models import SalaTematica, Mesa, Reserva
from usuarios.models import Cliente

class SalaTematicaSerializer(serializers.ModelSerializer):
    class Meta:
        model = SalaTematica
        fields = '__all__'

class MesaSerializer(serializers.ModelSerializer):
    sala_nombre = serializers.ReadOnlyField(source='sala.nombre')

    class Meta:
        model = Mesa
        fields = '__all__'

class ReservaSerializer(serializers.ModelSerializer):
    cliente_nombre = serializers.ReadOnlyField(source='cliente.id_usuario.nombre')
    sala_nombre = serializers.ReadOnlyField(source='sala.nombre')
    mesa_nombre = serializers.ReadOnlyField(source='mesa.nombre')

    class Meta:
        model = Reserva
        fields = '__all__'
