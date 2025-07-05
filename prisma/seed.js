const { PrismaClient } = require('@prisma/client')
const bcrypt = require('bcryptjs')

const prisma = new PrismaClient()

async function main() {
  // Cria usuário de exemplo
  const senhaHash = await bcrypt.hash('Admin@1234', 10)

  const usuario = await prisma.usuario.create({
    data: {
      nome: 'Admin',
      email: 'admin@hortifruti.com',
      senha: senhaHash,
      nivel: 3 // Admin
    }
  })

  console.log('Seed concluído com sucesso!')
}

main()
  .catch((e) => {
    console.error('Erro no seed:', e)
    process.exit(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
