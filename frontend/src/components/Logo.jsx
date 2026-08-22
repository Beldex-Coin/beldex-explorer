export default function Logo({ size = 30 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
      <circle cx="20" cy="20" r="17.5" stroke="#00d959" strokeWidth="3.4" />
      <path d="M14 11h8.2c3.2 0 5.2 1.7 5.2 4.3 0 1.9-1.1 3.3-2.7 3.9 2.1.5 3.5 2.1 3.5 4.3 0 2.9-2.2 4.7-5.6 4.7H14V11z" fill="#2f7dff" />
      <path d="M17.4 14v4.5h4.3c1.5 0 2.4-.9 2.4-2.3S23.2 14 21.7 14h-4.3zm0 7.4V26h4.9c1.6 0 2.5-.9 2.5-2.3s-1-2.3-2.5-2.3h-4.9z" fill="#0a0a0a" />
    </svg>
  )
}
