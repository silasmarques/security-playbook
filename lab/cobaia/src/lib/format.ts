const CORES = ["#f59e0b", "#10b981", "#3b82f6", "#ec4899"];

export function corAleatoria(): string {
  return CORES[Math.floor(Math.random() * CORES.length)];
}

export function dataBr(d: Date): string {
  return new Intl.DateTimeFormat("pt-BR").format(d);
}
