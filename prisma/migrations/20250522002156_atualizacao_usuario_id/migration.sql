-- CreateEnum
CREATE TYPE "Categoria" AS ENUM ('FRUTAS', 'LEGUMES', 'VERDURAS', 'TEMPEROS');

-- CreateEnum
CREATE TYPE "Status" AS ENUM ('EM_ANDAMENTO', 'FINALIZADO', 'CANCELADO', 'PENDENTE', 'ENTREGUE', 'EM_PREPARACAO', 'EM_ROTA', 'RETORNANDO');

-- CreateTable
CREATE TABLE "feirantes" (
    "id" SERIAL NOT NULL,
    "nome" VARCHAR(60) NOT NULL,
    "email" VARCHAR(60) NOT NULL,
    "senha" VARCHAR(60) NOT NULL,
    "telefone" VARCHAR(60) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "usuario_id" TEXT NOT NULL,

    CONSTRAINT "feirantes_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mercadorias" (
    "id" SERIAL NOT NULL,
    "nome" VARCHAR(60) NOT NULL,
    "preco" DECIMAL(10,2) NOT NULL,
    "quantidade" DECIMAL(10,2) NOT NULL,
    "categoria" "Categoria" NOT NULL DEFAULT 'FRUTAS',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "foto" TEXT NOT NULL,
    "feirante_id" INTEGER NOT NULL,
    "destaque" BOOLEAN NOT NULL DEFAULT true,
    "usuario_id" TEXT NOT NULL,

    CONSTRAINT "mercadorias_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "fotos_mercadoria" (
    "id" SERIAL NOT NULL,
    "descricao" VARCHAR(60) NOT NULL,
    "url" TEXT NOT NULL,
    "mercadoria_id" INTEGER NOT NULL,
    "feirante_id" INTEGER NOT NULL,

    CONSTRAINT "fotos_mercadoria_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "usuarios" (
    "id" VARCHAR(36) NOT NULL,
    "nome" VARCHAR(60) NOT NULL,
    "email" VARCHAR(60) NOT NULL,
    "senha" VARCHAR(60) NOT NULL,
    "nivel" INTEGER NOT NULL DEFAULT 1,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "usuarios_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pedidos" (
    "id" SERIAL NOT NULL,
    "status" "Status" NOT NULL DEFAULT 'EM_PREPARACAO',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3),
    "mercadoria_id" INTEGER NOT NULL,
    "usuario_id" VARCHAR(36) NOT NULL,

    CONSTRAINT "pedidos_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "feirantes" ADD CONSTRAINT "feirantes_usuario_id_fkey" FOREIGN KEY ("usuario_id") REFERENCES "usuarios"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mercadorias" ADD CONSTRAINT "mercadorias_feirante_id_fkey" FOREIGN KEY ("feirante_id") REFERENCES "feirantes"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "mercadorias" ADD CONSTRAINT "mercadorias_usuario_id_fkey" FOREIGN KEY ("usuario_id") REFERENCES "usuarios"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fotos_mercadoria" ADD CONSTRAINT "fotos_mercadoria_mercadoria_id_fkey" FOREIGN KEY ("mercadoria_id") REFERENCES "mercadorias"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fotos_mercadoria" ADD CONSTRAINT "fotos_mercadoria_feirante_id_fkey" FOREIGN KEY ("feirante_id") REFERENCES "feirantes"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pedidos" ADD CONSTRAINT "pedidos_mercadoria_id_fkey" FOREIGN KEY ("mercadoria_id") REFERENCES "mercadorias"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pedidos" ADD CONSTRAINT "pedidos_usuario_id_fkey" FOREIGN KEY ("usuario_id") REFERENCES "usuarios"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
