import React from 'react';
import { Row, Col, Card, Statistic } from 'antd';
import {
  ArrowUpOutlined,
  ArrowDownOutlined,
  StopOutlined,
  LinkOutlined,
} from '@ant-design/icons';
import { useCurrentStats } from '../hooks/useStats';
import { formatPPS, formatBPS, formatCount } from '../utils';

const StatsCards: React.FC = () => {
  const stats = useCurrentStats();

  const cards = [
    {
      title: 'Inbound Traffic',
      value: stats ? formatPPS(stats.rxPps) : '--',
      subtitle: stats ? formatBPS(stats.rxBps) : '--',
      icon: <ArrowDownOutlined style={{ color: '#1668dc' }} />,
      color: '#1668dc',
    },
    {
      title: 'Passed Traffic',
      value: stats ? formatPPS(stats.txPps) : '--',
      subtitle: stats ? formatBPS(stats.txBps) : '--',
      icon: <ArrowUpOutlined style={{ color: '#52c41a' }} />,
      color: '#52c41a',
    },
    {
      title: 'Dropped',
      value: stats ? formatPPS(stats.dropPps) : '--',
      subtitle: stats ? formatBPS(stats.dropBps) : '--',
      icon: <StopOutlined style={{ color: '#f5222d' }} />,
      color: '#f5222d',
    },
    {
      title: 'Connections',
      value: stats ? formatCount(stats.conntrackEstablished) : '--',
      subtitle: stats ? `${formatCount(stats.conntrackNew)} new` : '--',
      icon: <LinkOutlined style={{ color: '#13c2c2' }} />,
      color: '#13c2c2',
    },
  ];

  return (
    <Row gutter={[16, 16]}>
      {cards.map((card) => (
        <Col xs={24} sm={12} lg={6} key={card.title}>
          <Card size="small" hoverable>
            <Statistic
              title={card.title}
              value={card.value}
              prefix={card.icon}
              valueStyle={{ color: card.color, fontSize: 22 }}
            />
            <div
              style={{
                color: 'rgba(255,255,255,0.45)',
                fontSize: 12,
                marginTop: 4,
              }}
            >
              {card.subtitle}
            </div>
          </Card>
        </Col>
      ))}
    </Row>
  );
};

export default StatsCards;
