'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Wizard, { WizardData } from '@/components/Wizard';

export default function Home() {
  const [wizardComplete, setWizardComplete] = useState(false);
  const router = useRouter();

  const handleWizardComplete = (data: WizardData) => {
    setWizardData(data);
    setWizardComplete(true);

    // If FinOps concern is true, trigger backend notification
    if (data.finOpsConcern) {
      // TODO: Send notification to sales team
      console.log('FinOps review requested for customer');
    }

    // Redirect directly to /secure with wizard data as query params
    const params = new URLSearchParams({
      region: data.region,
      email: data.alertEmails.join(','),
      finops: data.finOpsConcern.toString()
    });
    router.push(`/secure?${params.toString()}`);
  };

  const [wizardData, setWizardData] = useState<WizardData | null>(null);

  return <Wizard onComplete={handleWizardComplete} />;
}

