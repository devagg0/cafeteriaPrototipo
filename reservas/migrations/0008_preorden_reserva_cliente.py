import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('reservas', '0007_producto_stock_reservado_preorden'),
        ('usuarios', '0009_usuario_foto_perfil'),
    ]

    operations = [
        # 1. FK reserva en Preorden
        migrations.AddField(
            model_name='preorden',
            name='reserva',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='preordenes',
                to='reservas.reserva',
            ),
        ),
        # 2. FK cliente en Preorden
        migrations.AddField(
            model_name='preorden',
            name='cliente',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='preordenes',
                to='usuarios.cliente',
            ),
        ),
    ]
