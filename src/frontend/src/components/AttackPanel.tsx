import React, { useMemo } from 'react';
import { Card, Row, Col } from 'antd';
import ReactECharts from 'echarts-for-react';
import { useCurrentStats } from '../hooks/useStats';
import { ATTACK_COLORS } from '../styles/theme';
import { formatCount } from '../utils';

const AttackPanel: React.FC = () => {
  const stats = useCurrentStats();

  const attackData = useMemo(() => {
    if (!stats) return [];
    return [
      { name: 'SYN Flood', value: stats.synFloodDropped, key: 'syn_flood' },
      { name: 'UDP Flood', value: stats.udpFloodDropped, key: 'udp_flood' },
      { name: 'ICMP Flood', value: stats.icmpFloodDropped, key: 'icmp_flood' },
      { name: 'ACK Flood', value: stats.ackFloodDropped, key: 'ack_flood' },
      { name: 'DNS Amp', value: stats.dnsAmpDropped, key: 'dns_amplification' },
      { name: 'NTP Amp', value: stats.ntpAmpDropped, key: 'ntp_amplification' },
      { name: 'Fragment', value: stats.fragmentDropped, key: 'fragment' },
      { name: 'ACL', value: stats.aclDropped, key: 'acl_dropped' },
      { name: 'Rate Limited', value: stats.rateLimited, key: 'rate_limited' },
    ].filter((d) => d.value > 0);
  }, [stats]);

  const pieOption = useMemo(() => {
    return {
      tooltip: {
        trigger: 'item' as const,
        backgroundColor: '#1f1f1f',
        borderColor: '#424242',
        textStyle: { color: '#fff' },
        formatter: (p: { name: string; value: number; percent: number }) =>
          `${p.name}: ${formatCount(p.value)} (${p.percent.toFixed(1)}%)`,
      },
      series: [
        {
          type: 'pie',
          radius: ['40%', '70%'],
          center: ['50%', '50%'],
          avoidLabelOverlap: true,
          itemStyle: {
            borderRadius: 4,
            borderColor: '#1f1f1f',
            borderWidth: 2,
          },
          label: {
            color: 'rgba(255,255,255,0.65)',
            fontSize: 11,
          },
          data: attackData.map((d) => ({
            name: d.name,
            value: d.value,
            itemStyle: {
              color: ATTACK_COLORS[d.key] || '#999',
            },
          })),
        },
      ],
    };
  }, [attackData]);

  const synCookieData = useMemo(() => {
    if (!stats) return null;
    return {
      sent: stats.synCookiesSent,
      validated: stats.synCookiesValidated,
      failed: stats.synCookiesFailed,
      successRate:
        stats.synCookiesSent > 0
          ? ((stats.synCookiesValidated / stats.synCookiesSent) * 100).toFixed(1)
          : '0',
    };
  }, [stats]);

  return (
    <Row gutter={[16, 16]}>
      <Col xs={24} lg={14}>
        <Card title="Drop Breakdown" size="small">
          {attackData.length > 0 ? (
            <ReactECharts
              option={pieOption}
              style={{ height: 260 }}
              opts={{ renderer: 'canvas' }}
            />
          ) : (
            <div
              style={{
                height: 260,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'rgba(255,255,255,0.25)',
              }}
            >
              No drops detected
            </div>
          )}
        </Card>
      </Col>

      <Col xs={24} lg={10}>
        <Card title="SYN Cookie" size="small">
          <div style={{ padding: '16px 0' }}>
            {[
              { label: 'Challenges Sent', value: synCookieData?.sent ?? 0 },
              { label: 'Validated', value: synCookieData?.validated ?? 0 },
              { label: 'Failed', value: synCookieData?.failed ?? 0 },
              {
                label: 'Success Rate',
                value: `${synCookieData?.successRate ?? 0}%`,
              },
            ].map((item) => (
              <div
                key={item.label}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  padding: '8px 0',
                  borderBottom: '1px solid #303030',
                }}
              >
                <span style={{ color: 'rgba(255,255,255,0.65)' }}>
                  {item.label}
                </span>
                <span style={{ color: '#fff', fontWeight: 500 }}>
                  {typeof item.value === 'number'
                    ? formatCount(item.value)
                    : item.value}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </Col>
    </Row>
  );
};

export default AttackPanel;
