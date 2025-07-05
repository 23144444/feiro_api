import { Request, Response, NextFunction } from "express";

export function verificaNivel(minNivel: number) {
  return (req: Request | any, res: Response, next: NextFunction) => {
    if (!req.userLogadoNivel || req.userLogadoNivel < minNivel) {
      res.status(403).json({ error: "Acesso negado. Nível insuficiente." });
      return;
    }
    next();
  };
}
