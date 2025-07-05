/*
  Warnings:

  - A unique constraint covering the columns `[email]` on the table `feirantes` will be added. If there are existing duplicate values, this will fail.

*/
-- DropForeignKey
ALTER TABLE "fotos_mercadoria" DROP CONSTRAINT "fotos_mercadoria_feirante_id_fkey";

-- DropForeignKey
ALTER TABLE "fotos_mercadoria" DROP CONSTRAINT "fotos_mercadoria_mercadoria_id_fkey";

-- DropForeignKey
ALTER TABLE "pedidos" DROP CONSTRAINT "pedidos_mercadoria_id_fkey";

-- DropForeignKey
ALTER TABLE "pedidos" DROP CONSTRAINT "pedidos_usuario_id_fkey";

-- CreateTable
CREATE TABLE "mensagens" (
    "id" SERIAL NOT NULL,
    "conteudo" VARCHAR(255) NOT NULL,

    CONSTRAINT "mensagens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "enderecos" (
    "id" SERIAL NOT NULL,
    "latitude" DOUBLE PRECISION NOT NULL,
    "longitude" DOUBLE PRECISION NOT NULL,

    CONSTRAINT "enderecos_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "feirantes_email_key" ON "feirantes"("email");

-- AddForeignKey
ALTER TABLE "fotos_mercadoria" ADD CONSTRAINT "fotos_mercadoria_mercadoria_id_fkey" FOREIGN KEY ("mercadoria_id") REFERENCES "mercadorias"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "fotos_mercadoria" ADD CONSTRAINT "fotos_mercadoria_feirante_id_fkey" FOREIGN KEY ("feirante_id") REFERENCES "feirantes"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pedidos" ADD CONSTRAINT "pedidos_mercadoria_id_fkey" FOREIGN KEY ("mercadoria_id") REFERENCES "mercadorias"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pedidos" ADD CONSTRAINT "pedidos_usuario_id_fkey" FOREIGN KEY ("usuario_id") REFERENCES "usuarios"("id") ON DELETE CASCADE ON UPDATE CASCADE;
