import { ArrowUpRight, Construction } from 'lucide-react'
import { Link } from 'react-router-dom'

export default function SectionPlaceholder({ eyebrow, title, description, icon: Icon }) {
  return (
    <div className="placeholder-page">
      <div className="eyebrow"><span className="eyebrow__line" /> {eyebrow}</div>
      <div className="placeholder-card panel">
        <div className="placeholder-card__icon"><Icon size={35} strokeWidth={1.4} /></div>
        <div className="placeholder-card__status"><Construction size={15} /> FOUNDATION READY</div>
        <h1>{title}</h1>
        <p>{description}</p>
        <div className="placeholder-card__rule" />
        <div className="placeholder-card__footer"><span>This workspace is connected to the ChainGuard API. Detailed views will follow.</span><Link to="/">Return to dashboard <ArrowUpRight size={16} /></Link></div>
      </div>
    </div>
  )
}
