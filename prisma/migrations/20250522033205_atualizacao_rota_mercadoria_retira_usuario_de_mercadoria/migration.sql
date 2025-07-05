/*
  Warnings:

  - You are about to drop the column `usuario_id` on the `mercadorias` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "mercadorias" DROP CONSTRAINT "mercadorias_usuario_id_fkey";

-- AlterTable
ALTER TABLE "mercadorias" DROP COLUMN "usuario_id";
