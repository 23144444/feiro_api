-- AlterTable
ALTER TABLE "usuarios" ADD COLUMN     "codigoRecuperacao" TEXT,
ADD COLUMN     "endereco" VARCHAR(60) NOT NULL DEFAULT '',
ADD COLUMN     "telefone" VARCHAR(60) NOT NULL DEFAULT '';
