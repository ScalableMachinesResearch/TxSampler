// $Id$
// -*-C++-*-
// * BeginRiceCopyright *****************************************************
// 
// Copyright ((c)) 2002, Rice University 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// 
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
// 
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
// 
// * Neither the name of Rice University (RICE) nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
// 
// This software is provided by RICE and contributors "as is" and any
// express or implied warranties, including, but not limited to, the
// implied warranties of merchantability and fitness for a particular
// purpose are disclaimed. In no event shall RICE or contributors be
// liable for any direct, indirect, incidental, special, exemplary, or
// consequential damages (including, but not limited to, procurement of
// substitute goods or services; loss of use, data, or profits; or
// business interruption) however caused and on any theory of liability,
// whether in contract, strict liability, or tort (including negligence
// or otherwise) arising in any way out of the use of this software, even
// if advised of the possibility of such damage. 
// 
// ******************************************************* EndRiceCopyright *

//***************************************************************************
//
// File:
//    DCPIProfile.h
//
// Purpose:
//    [The purpose of this file]
//
// Description:
//    See, in particular, the comments associated with 'DCPIProfile'.
//
//***************************************************************************

#ifndef DCPIProfile_H 
#define DCPIProfile_H

//************************* System Include Files ****************************

#include <vector>
#include <map>

#include "inttypes.h"

//*************************** User Include Files ****************************

#include <include/general.h>

#include "PCProfile.h"
#include "DCPIProfileMetric.h"
#include "DCPIProfileFilter.h"

#include <lib/ISA/ISATypes.h>
#include <lib/support/String.h>
#include <lib/support/Assertion.h>

//*************************** Forward Declarations ***************************

//****************************************************************************
// DCPIProfile
//****************************************************************************

// 'DCPIProfile' extensions to 'PCProfile' for representing data
// resulting from DEC/Compaq/HP DCPI profiles (including ProfileMe).
class DCPIProfile : public PCProfile
{
public:
  DCPIProfile(suint sz = 200);
  virtual ~DCPIProfile();
 
  // Access to 'DCPIProfileMetric' (includes casts)
  const DCPIProfileMetric* DCPIGetMetric(suint i) const { 
    return dynamic_cast<const DCPIProfileMetric*>(Index(i)); 
  }
  void SetDCPIMetric(suint i, DCPIProfileMetric* m) { Assign(i, m); }
 
  void Dump(std::ostream& o = std::cerr);
  void DDump(); 
  
private:
  // Should not be used 
  DCPIProfile(const DCPIProfile& p) { }
  DCPIProfile& operator=(const DCPIProfile& p) { return *this; }
  
  friend class DCPIProfileMetricSetIterator;
  
protected:
private:
  
};

// 'DCPIProfileMetricSetIterator' iterates over all 'DCPIProfileMetric'
// within a 'DCPIProfile'.
class DCPIProfileMetricSetIterator
{
public:
  DCPIProfileMetricSetIterator(const DCPIProfile& x) 
    : p(x), it(x) { }
  virtual ~DCPIProfileMetricSetIterator() { }
  
  DCPIProfileMetric* Current() { 
    return dynamic_cast<DCPIProfileMetric*>(it.Current()); 
  }
  
  void operator++()    { it++; } // prefix
  void operator++(int) { ++it; } // postfix
  
  bool IsValid() const { return it.IsValid(); }
  bool IsEmpty() const { return it.IsEmpty(); }
  
  // Reset and prepare for iteration again
  void Reset()  { it.Reset(); }
  
private:
  // Should not be used  
  DCPIProfileMetricSetIterator();
  DCPIProfileMetricSetIterator(const DCPIProfileMetricSetIterator& x);
  DCPIProfileMetricSetIterator& operator=(const DCPIProfileMetricSetIterator& x) 
    { return *this; }
  
protected:
private:
  const DCPIProfile& p;
  PCProfileMetricSetIterator it;
};

//****************************************************************************

#endif 

