const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
const SECONDS_PER_DAY = 86400;

const daysFromCivil = (year: number, month: number, day: number): number => {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.floor(y / 400);
  const yearOfEra = y - era * 400;
  const dayOfYear = Math.floor((153 * (month + (month > 2 ? -3 : 9)) + 2) / 5) + day - 1;
  const dayOfEra =
    yearOfEra * 365 + Math.floor(yearOfEra / 4) - Math.floor(yearOfEra / 100) + dayOfYear;
  return era * 146097 + dayOfEra - 719468;
};

const daysInMonth = (year: number, month: number): number => {
  if (month === 2) {
    return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0 ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
};

export const parseIden3JwzDate = (text: string): number | null => {
  const match = DATE_PATTERN.exec(text);
  if (!match) {
    return null;
  }
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  if (day > daysInMonth(year, month)) {
    return null;
  }
  return daysFromCivil(year, month, day) * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second;
};

export const formatIden3JwzDate = (seconds: number): string =>
  new Date(seconds * 1000).toISOString().replace('.000Z', 'Z');
