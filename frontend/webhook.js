export const deliveryLabels = {
  PENDING: "Ожидает отчёт",
  SENDING: "Отправляется",
  SENT: "Доставлено",
  FAILED: "Ошибка доставки",
  NOT_CONFIGURED: "URL не настроен",
  SKIPPED: "Пропущено",
};

export function deliveryDetails(event) {
  const { http_status: httpStatus, attempts } = event.output ?? {};
  const details = [];
  if (Number.isInteger(httpStatus)) details.push(`HTTP ${httpStatus}`);
  if (Number.isInteger(attempts) && attempts > 0) details.push(`Попыток: ${attempts}`);
  return details.join(" · ");
}
