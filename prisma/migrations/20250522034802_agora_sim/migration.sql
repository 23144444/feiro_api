/*
  Warnings:

  - You are about to drop the column `usuario_id` on the `feirantes` table. All the data in the column will be lost.

*/
-- DropForeignKey
ALTER TABLE "feirantes" DROP CONSTRAINT "feirantes_usuario_id_fkey";

-- AlterTable
ALTER TABLE "feirantes" DROP COLUMN "usuario_id";
