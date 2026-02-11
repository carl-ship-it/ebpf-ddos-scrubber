import React, { useMemo } from 'react';
import { Row, Col, Card, Typography } from 'antd';
import {
  ArrowUpOutlined,
  ArrowDownOutlined,
  StopOutlined,
  LinkOutlined,
  CaretUpOutlined,
  CaretDownOutlined,
} from '@ant-design/icons';
import ReactECharts from 'echarts-for-react';
import { useCurrentStats, useStatsHistory } from '../hooks/useStats';
import { formatPPS, formatBPS, formatCount } from '../utils';
import type { StatsSnapshot } from '../types';

const { Text } = Typography;

interface CardDef {
  title: string;
  value: string;
  subtitle: string;
  icon: React.ReactNode;
  color: string;
  sparkData: number[];
  trend: number; // percentage change
}

const StatsCards: React.FC = () => {
  const stats = useCurrentStats();
  const history = useStatsHistory();

  const cards: CardDef[] = useMemo(() => {
    if (!stats) {
      return [
        { title: 'Inbound Traffic', value: '--', subtitle: '--', icon: <ArrowDownOutlined style={{ color: '#1668dc' }} />, color: '#1668dc', sparkData: [], trend: 0 },
        { title: 'Passed Traffic', value: '--', subtitle: '--', icon: <ArrowUpOutlined style={{ color: '#52c41a' }} />, color: '#52c41a', sparkData: [], trend: 0 },
        { title: 'Dropped', value: '--', subtitle: '--', icon: <StopOutlined style={{ color: '#f5222d' }} />, color: '#f5222d', sparkData: [], trend: 0 },
        { title: 'Connections', value: '--', subtitle: '--', icon: <LinkOutlined style={{ color: '#13c2c2' }} />, color: '#13c2c2', sparkData: [], trend: 0 },
      ];
    }

    const recent = history.slice(-30);
    const calcTrend = (getter: (s: StatsSnapshot) => number) => {
      if (recent.length < 10) return 0;
      const oldAvg = recent.slice(0, 5).reduce((sum, s) => sum + getter(s), 0) / 5;
      const newAvg = recent.slice(-5).reduce((sum, s) => sum + getter(s), 0) / 5;
      if (oldAvg === 0) return 0;
      return ((newAvg - oldAvg) / oldAvg) * 100;
    };

    return [
      {
        title: 'Inbound Traffic',
        value: formatPPS(stats.rxPps),
        subtitle: formatBPS(stats.rxBps),
        icon: <ArrowDownOutlined />,
        color: '#1668dc',
        sparkData: recent.map((s) => s.rxPps),
        trend: calcTrend((s) => s.rxPps),
      },
      {
        title: 'Passed Traffic',
        value: formatPPS(stats.txPps),
        subtitle: formatBPS(stats.txBps),
        icon: <ArrowUpOutlined />,
        color: '#52c41a',
        sparkData: recent.map((s) => s.txPps),
        trend: calcTrend((s) => s.txPps),
      },
      {
        title: 'Dropped',
        value: formatPPS(stats.dropPps),
        subtitle: formatBPS(stats.dropBps),
        icon: <StopOutlined />,
        color: '#f5222d',
        sparkData: recent.map((s) => s.dropPps),
        trend: calcTrend((s) => s.dropPps),
      },
      {
        title: 'Connections',
        value: formatCount(stats.conntrackEstablished),
        subtitle: `${formatCount(stats.conntrackNew)} new/s`,
        icon: <LinkOutlined />,
        color: '#13c2c2',
        sparkData: recent.map((s) => s.conntrackEstablished),
        trend: calcTrend((s) => s.conntrackEstablished),
      },
    ];
  }, [stats, history]);

  return (
    <Row gutter={[12, 12]}>
      {cards.map((card) => {
        const sparkOption = card.sparkData.length > 2 ? {
          grid: { left: 0, right: 0, top: 0, bottom: 0 },
          xAxis: { type: 'category' as const, show: false, data: card.sparkData.map((_, i) => i) },
          yAxis: { type: 'value' as const, show: false },
          series: [{
            type: 'line',
            data: card.sparkData,
            smooth: true,
            showSymbol: false,
            lineStyle: { width: 1.5, color: card.color },
            areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1, colorStops: [{ offset: 0, color: card.color + '40' }, { offset: 1, color: card.color + '05' }] } },
          }],
        } : null;

        const trendUp = card.trend > 2;
        const trendDown = card.trend < -2;
        const trendColor = card.title === 'Dropped'
          ? (trendUp ? '#f5222d' : trendDown ? '#52c41a' : 'rgba(255,255,255,0.3)')
          : (trendUp ? '#52c41a' : trendDown ? '#f5222d' : 'rgba(255,255,255,0.3)');

        return (
          <Col xs={24} sm={12} lg={6} key={card.title}>
            <Card
              size="small"
              hoverable
              style={{
                borderLeft: `3px solid ${card.color}`,
                background: 'linear-gradient(135deg, #1a1a2e 0%, #1f1f1f 100%)',
              }}
              bodyStyle={{ padding: '12px 16px' }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ color: 'rgba(255,255,255,0.45)', fontSize: 12, marginBottom: 4 }}>
                    {card.title}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
                    <Text strong style={{ color: card.color, fontSize: 22, lineHeight: 1 }}>
                      {card.value}
                    </Text>
                    {(trendUp || trendDown) && (
                      <span style={{ color: trendColor, fontSize: 12, display: 'flex', alignItems: 'center', gap: 2 }}>
                        {trendUp ? <CaretUpOutlined /> : <CaretDownOutlined />}
                        {Math.abs(card.trend).toFixed(0)}%
                      </span>
                    )}
                  </div>
                  <div style={{ color: 'rgba(255,255,255,0.35)', fontSize: 11, marginTop: 2 }}>
                    {card.subtitle}
                  </div>
                </div>
                {sparkOption && (
                  <div style={{ width: 80, height: 36, marginTop: 4 }}>
                    <ReactECharts
                      option={sparkOption}
                      style={{ height: 36, width: 80 }}
                      opts={{ renderer: 'canvas' }}
                    />
                  </div>
                )}
              </div>
            </Card>
          </Col>
        );
      })}
    </Row>
  );
};

export default StatsCards;
