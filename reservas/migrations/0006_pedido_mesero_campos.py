import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reservas', '0005_categoria_pedido_producto_detallepedido'),
        ('usuarios', '0009_usuario_foto_perfil'),
    ]

    operations = [
        # 1. Hacer nullable la FK reserva en Pedido
        migrations.AlterField(
            model_name='pedido',
            name='reserva',
            field=models.OneToOneField(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='pedido',
                to='reservas.reserva',
            ),
        ),

        # 2. Agregar FK sala a Pedido
        migrations.AddField(
            model_name='pedido',
            name='sala',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='pedidos_directos',
                to='reservas.salatematica',
            ),
        ),

        # 3. Agregar FK mesa a Pedido
        migrations.AddField(
            model_name='pedido',
            name='mesa',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='pedidos_directos',
                to='reservas.mesa',
            ),
        ),

        # 4. Agregar estado 'atendida' a Mesa
        migrations.AlterField(
            model_name='mesa',
            name='estado',
            field=models.CharField(
                choices=[
                    ('disponible', 'Disponible'),
                    ('ocupada', 'Ocupada'),
                    ('reservada', 'Reservada'),
                    ('atendida', 'Atendida'),
                ],
                default='disponible',
                max_length=20,
            ),
        ),
    ]
