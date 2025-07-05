import { Categoria, PrismaClient } from '@prisma/client'
import { Router } from 'express'
import { z } from 'zod'

const prisma = new PrismaClient()

const router = Router()

const mercadoriaSchema = z.object({
  nome: z.string().min(2,
    { message: "Nome deve possuir, no mínimo, 2 caracteres" }),
  preco: z.number(),
  quantidade: z.number(),
  categoria: z.nativeEnum(Categoria).optional(),
  foto: z.string(),
  destaque: z.boolean().optional(),
  feirante_id: z.number()
  // usuario_id: z.string()
})

router.get("/", async (req, res) => {
  try {
    const mercadorias = await prisma.mercadoria.findMany({
      include: {
        feirante: true,
        fotos: true
      }
    })
    res.status(200).json(mercadorias)
  } catch (error) {
    res.status(500).json({ erro: error })
  }
})

router.post("/", async (req, res) => {

  const valida = mercadoriaSchema.safeParse(req.body)
  if (!valida.success) {
    res.status(400).json({ erro: valida.error })
    return
  }

  const { nome, preco, quantidade, categoria = 'FRUTAS', foto,
    destaque = true,  feirante_id } = valida.data

  try {
    const mercadoria = await prisma.mercadoria.create({
      data: {
        nome, preco, quantidade, categoria, foto, destaque, feirante_id,
      }
    })
    res.status(201).json(mercadoria)
  } catch (error) {
    res.status(400).json({ error })
  }
})

router.delete("/:id", async (req, res) => {
  const { id } = req.params

  try {
    const mercadoria = await prisma.mercadoria.delete({
      where: { id: Number(id) }
    })
    res.status(200).json(mercadoria)
  } catch (error) {
    res.status(400).json({ erro: error })
  }
})

router.put("/:id", async (req, res) => {
  const { id } = req.params

  const valida = mercadoriaSchema.safeParse(req.body)
  if (!valida.success) {
    res.status(400).json({ erro: valida.error })
    return
  }

  const { nome, preco, quantidade, categoria, foto, destaque, feirante_id } = valida.data

  try {
    const mercadoria = await prisma.mercadoria.update({
      where: { id: Number(id) },
      data: {
        nome, preco, quantidade, categoria, foto, destaque, feirante_id
      }
    })
    res.status(200).json(mercadoria)
  } catch (error) {
    res.status(400).json({ error })
  }
})

router.get("/pesquisa/:termo", async (req, res) => {
  const { termo } = req.params

  // tenta converter para número
  const termoNumero = Number(termo)

  // is Not a Number, ou seja, se não é um número: filtra por texto
  if (isNaN(termoNumero)) {
    try {
      const termoUpperCase = termo.toUpperCase();
      const categorias = ["FRUTAS", "LEGUMES", "VERDURAS", "TEMPEROS"];
      const isCategoriaValida = categorias.includes(termoUpperCase); 

      const mercadorias = await prisma.mercadoria.findMany({
        include: {
          feirante: true,
        },
        // mode sensitive (Para não diferenciar maiuscula de minúsculas)
        // necessário no PostgreSQL (NO MySQL é o padrão)
        where: {
          OR: [
            { nome: { contains: termo, mode: "insensitive" } },
            { feirante: { nome: { equals: termo, mode: "insensitive" } } },
            ...(isCategoriaValida ? [{ 
              categoria: termoUpperCase as "FRUTAS" | "LEGUMES" | "VERDURAS" | "TEMPEROS"
            }] : [])
          ]
        }
      })
      res.status(200).json(mercadorias)
    } catch (error) {
      res.status(500).json({ erro: error })
    }
  } else {
    try {
      const mercadorias = await prisma.mercadoria.findMany({
        include: {
          feirante: true,
        },
        where: { 
          preco: { lte: termoNumero } 
        }
      })
      res.status(200).json(mercadorias)
    } catch (error: unknown) {
      if (error instanceof Error) {
        res.status(500).json({ erro: error.message })
      } else {
        res.status(500).json({ erro: "Erro desconhecido" })
      }
    }
}})

// Rota de Consulta de mercadoria pelo Id, retorna um OBJETO, não um ARRAY
router.get("/:id", async (req, res) => {
  const { id } = req.params

  try {
    const mercadoria = await prisma.mercadoria.findUnique({
      where: { id: Number(id)},
      include: {
        feirante: true
      }
    })
    res.status(200).json(mercadoria)
  } catch (error) {
    res.status(400).json(error)
  }
})

router.patch("/:id", async (req, res) => {
  const { id } = req.params;

  const dadosAlteracao = req.body;

  const camposPermitidos = ['nome', 'preco', 'quantidade'];
  const campoASerAlterado = Object.keys(dadosAlteracao)[0]; 

  if (!camposPermitidos.includes(campoASerAlterado)) {
    return res.status(400).json({ erro: `O campo '${campoASerAlterado}' não pode ser alterado.` });
  }

  try {
    const mercadoriaAtualizada = await prisma.mercadoria.update({
      where: {
        id: Number(id),
      },
  
      data: dadosAlteracao,
    });
    
    res.status(200).json(mercadoriaAtualizada);
  } catch (error) {
    res.status(500).json({ error });
  }
});

export default router
