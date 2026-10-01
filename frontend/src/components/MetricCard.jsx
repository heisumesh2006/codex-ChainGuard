import { motion } from 'framer-motion'
import { ArrowUpRight } from 'lucide-react'
import AnimatedNumber from './AnimatedNumber'

export default function MetricCard({ label, value, detail, icon: Icon, tone = 'cyan', index = 0, suffix = '', decimals = 0 }) {
  return (
    <motion.article
      className={`metric-card metric-card--${tone}`}
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.38, delay: index * 0.06 }}
    >
      <div className="metric-card__top">
        <span className="metric-card__icon"><Icon size={19} strokeWidth={1.7} /></span>
        <ArrowUpRight size={16} className="metric-card__corner" />
      </div>
      <div className="metric-card__value"><AnimatedNumber value={value} suffix={suffix} decimals={decimals} /></div>
      <div className="metric-card__label">{label}</div>
      <div className="metric-card__detail">{detail}</div>
    </motion.article>
  )
}
