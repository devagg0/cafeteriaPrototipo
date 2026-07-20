from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pedidos', '0005_pedido_descuento_pedido_promocion'),
    ]

    operations = [
        migrations.AddField(
            model_name='detallepreorden',
            name='observaciones',
            field=models.TextField(blank=True, null=True),
        ),
    ]
