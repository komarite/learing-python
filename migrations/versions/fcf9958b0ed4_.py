"""empty message

Revision ID: fcf9958b0ed4
Revises: cd93d9ed803f
Create Date: 2022-04-28 23:05:35.880467

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fcf9958b0ed4'
down_revision = 'cd93d9ed803f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('blog_post', sa.Column('point', sa.Integer(), nullable=False))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('blog_post', 'point')
    # ### end Alembic commands ###
